use crate::config::{Committee, Stake};
use crate::core::{SeqNumber, RBC_ECHO, RBC_READY};
use crate::error::{ConsensusError, ConsensusResult};
use crate::messages::{EchoVote, RBCProof, RandomnessShare, ReadyVote, SMVBAProof, SMVBAVote};
use crypto::{PublicKey, SecretKey, Signature};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::convert::TryInto;
use threshold_crypto::PublicKeySet;

#[cfg(test)]
#[path = "tests/aggregator_tests.rs"]
pub mod aggregator_tests;

// In HotStuff, votes/timeouts aggregated by round
// In VABA and async fallback, votes aggregated by round, timeouts/coin_share aggregated by view
pub struct Aggregator {
    committee: Committee,
    share_coin_aggregators: HashMap<(SeqNumber, SeqNumber), Box<RandomCoinMaker>>,
    echo_vote_aggregators: HashMap<(SeqNumber, SeqNumber), Box<RBCProofMaker>>,
    ready_vote_aggregators: HashMap<(SeqNumber, SeqNumber), Box<RBCProofMaker>>,
    smvba_spb_vote_aggregators: HashMap<(SeqNumber, SeqNumber, u8), Box<SMVBAProofMaker>>,
}

impl Aggregator {
    pub fn new(committee: Committee) -> Self {
        Self {
            committee,
            share_coin_aggregators: HashMap::new(),
            echo_vote_aggregators: HashMap::new(),
            ready_vote_aggregators: HashMap::new(),
            smvba_spb_vote_aggregators: HashMap::new(),
        }
    }

    pub fn add_rbc_echo_vote(&mut self, vote: &EchoVote) -> ConsensusResult<Option<RBCProof>> {
        self.echo_vote_aggregators
            .entry((vote.epoch, vote.height))
            .or_insert_with(|| Box::new(RBCProofMaker::new()))
            .append(
                vote.epoch,
                vote.height,
                vote.author,
                RBC_ECHO,
                vote.signature.clone(),
                &self.committee,
            )
    }

    pub fn add_rbc_ready_vote(&mut self, vote: &ReadyVote) -> ConsensusResult<Option<RBCProof>> {
        self.ready_vote_aggregators
            .entry((vote.epoch, vote.height))
            .or_insert_with(|| Box::new(RBCProofMaker::new()))
            .append(
                vote.epoch,
                vote.height,
                vote.author,
                RBC_READY,
                vote.signature.clone(),
                &self.committee,
            )
    }

    pub fn add_smvba_spb_vote(&mut self, vote: &SMVBAVote) -> ConsensusResult<Option<SMVBAProof>> {
        self.smvba_spb_vote_aggregators
            .entry((vote.epoch, vote.round, vote.phase))
            .or_insert_with(|| Box::new(SMVBAProofMaker::new()))
            .append(vote, &self.committee)
    }

    pub fn add_smvba_share_coin(
        &mut self,
        share: &RandomnessShare,
        pk_set: &PublicKeySet,
    ) -> ConsensusResult<Option<PublicKey>> {
        self.share_coin_aggregators
            .entry((share.epoch, share.round))
            .or_insert_with(|| Box::new(RandomCoinMaker::new()))
            .append(share, &self.committee, pk_set)
    }

    pub fn cleanup(&mut self, epoch: SeqNumber) {
        self.echo_vote_aggregators.retain(|(e, ..), _| *e > epoch);
        self.ready_vote_aggregators.retain(|(e, ..), _| *e > epoch);
        self.share_coin_aggregators.retain(|(e, ..), _| *e > epoch);
        self.smvba_spb_vote_aggregators
            .retain(|(e, ..), _| *e > epoch);
    }
}

struct RBCProofMaker {
    weight: Stake,
    votes: Vec<(PublicKey, Signature)>,
    used: HashSet<PublicKey>,
}

impl RBCProofMaker {
    pub fn new() -> Self {
        Self {
            weight: 0,
            votes: Vec::new(),
            used: HashSet::new(),
        }
    }

    /// Try to append a signature to a (partial) quorum.
    pub fn append(
        &mut self,
        epoch: SeqNumber,
        height: SeqNumber,
        author: PublicKey,
        tag: u8,
        siganture: Signature,
        committee: &Committee,
    ) -> ConsensusResult<Option<RBCProof>> {
        // Ensure it is the first time this authority votes.
        ensure!(
            self.used.insert(author),
            ConsensusError::AuthorityReuseinRBCVote(author)
        );
        self.votes.push((author, siganture));
        self.weight += committee.stake(&author);

        if self.weight == committee.quorum_threshold()
            || (tag == RBC_READY && self.weight == committee.random_coin_threshold())
        {
            let proof = RBCProof::new(epoch, height, self.votes.clone(), tag);
            return Ok(Some(proof));
        }
        Ok(None)
    }
}

struct RandomCoinMaker {
    weight: Stake,
    shares: Vec<RandomnessShare>,
    used: HashSet<PublicKey>,
}

impl RandomCoinMaker {
    pub fn new() -> Self {
        Self {
            weight: 0,
            shares: Vec::new(),
            used: HashSet::new(),
        }
    }

    /// Try to append a signature to a (partial) quorum.
    pub fn append(
        &mut self,
        share: &RandomnessShare,
        committee: &Committee,
        pk_set: &PublicKeySet,
    ) -> ConsensusResult<Option<PublicKey>> {
        let author = share.author;
        // Ensure it is the first time this authority votes.
        ensure!(
            self.used.insert(author),
            ConsensusError::AuthorityReuseinCoin(author)
        );
        self.shares.push(share.clone());
        self.weight += committee.stake(&author);
        if self.weight == committee.random_coin_threshold() {
            // self.weight = 0; // Ensures QC is only made once.
            let mut sigs = BTreeMap::new();
            // Check the random shares.
            for share in self.shares.clone() {
                sigs.insert(
                    committee.id(share.author.clone()),
                    share.signature_share.clone(),
                );
            }
            if let Ok(sig) = pk_set.combine_signatures(sigs.iter()) {
                let id = usize::from_be_bytes((&sig.to_bytes()[0..8]).try_into().unwrap());
                let mut keys: Vec<_> = committee.authorities.keys().cloned().collect();
                keys.sort();
                let leader = keys[id];
                return Ok(Some(leader));
            }
        }
        Ok(None)
    }
}

struct SMVBAProofMaker {
    weight: Stake,
    votes: Vec<(PublicKey, Signature)>,
    used: HashSet<PublicKey>,
}

impl SMVBAProofMaker {
    pub fn new() -> Self {
        Self {
            weight: 0,
            votes: Vec::new(),
            used: HashSet::new(),
        }
    }

    /// Try to append a signature to a (partial) quorum.
    pub fn append(
        &mut self,
        vote: &SMVBAVote,
        committee: &Committee,
    ) -> ConsensusResult<Option<SMVBAProof>> {
        // Ensure it is the first time this authority votes.
        ensure!(
            self.used.insert(vote.author),
            ConsensusError::AuthorityReuseinRBCVote(vote.author)
        );
        self.votes.push((vote.author, vote.signature.clone()));
        self.weight += committee.stake(&vote.author);

        if self.weight == committee.quorum_threshold() {
            let proof = SMVBAProof::new(
                vote.proposer,
                vote.epoch,
                vote.height,
                vote.round,
                vote.phase,
            );
            return Ok(Some(proof));
        }
        Ok(None)
    }
}
