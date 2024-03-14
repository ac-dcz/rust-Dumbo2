use crate::config::Committee;
use crate::core::{SeqNumber, FINISH_PHASE, LOCK_PHASE, OPT};
use crate::error::{ConsensusError, ConsensusResult};
use crypto::{Digest, Hash, PublicKey, Signature, SignatureService};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fmt;
use threshold_crypto::{PublicKeySet, SignatureShare};

#[cfg(test)]
#[path = "tests/messages_tests.rs"]
pub mod messages_tests;

// daniel: Add view, height, fallback in Block, Vote and QC
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Block {
    pub author: PublicKey,
    pub epoch: SeqNumber,  //
    pub height: SeqNumber, // author`s id
    pub payload: Vec<Digest>,
    pub signature: Signature,
}

impl Block {
    pub async fn new(
        author: PublicKey,
        epoch: SeqNumber,
        height: SeqNumber,
        payload: Vec<Digest>,
        mut signature_service: SignatureService,
    ) -> Self {
        let block = Self {
            author,
            epoch,
            height,
            payload,
            signature: Signature::default(),
        };

        let signature = signature_service.request_signature(block.digest()).await;
        Self { signature, ..block }
    }

    pub fn genesis() -> Self {
        Block::default()
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(
            voting_rights > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature.verify(&self.digest(), &self.author)?;

        Ok(())
    }

    // block`s rank
    pub fn rank(&self, committee: &Committee) -> usize {
        let r = (self.epoch as usize) * committee.size() + (self.height as usize);
        r
    }
}

impl Hash for Block {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.height.to_le_bytes());
        for x in &self.payload {
            hasher.update(x);
        }
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: B(author {}, epoch {},  height {}, payload_len {})",
            self.digest(),
            self.author,
            self.epoch,
            self.height,
            self.payload.iter().map(|x| x.size()).sum::<usize>(),
        )
    }
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: B(author {}, epoch {},  height {}, payload_len {})",
            self.digest(),
            self.author,
            self.epoch,
            self.height,
            self.payload.iter().map(|x| x.size()).sum::<usize>(),
        )
    }
}

/************************** RBC Struct ************************************/
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct EchoVote {
    pub author: PublicKey,
    pub epoch: SeqNumber,
    pub height: SeqNumber,
    pub digest: Digest,
    pub signature: Signature,
}

impl EchoVote {
    pub async fn new(
        author: PublicKey,
        epoch: SeqNumber,
        height: SeqNumber,
        block: &Block,
        mut signature_service: SignatureService,
    ) -> Self {
        let mut vote = Self {
            author,
            epoch,
            height,
            digest: block.digest(),
            signature: Signature::default(),
        };
        vote.signature = signature_service.request_signature(vote.digest()).await;
        return vote;
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(
            voting_rights > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature.verify(&self.digest(), &self.author)?;

        Ok(())
    }

    pub fn rank(&self, committee: &Committee) -> usize {
        let r = (self.epoch as usize) * committee.size() + (self.height as usize);
        r
    }
}

impl Hash for EchoVote {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.digest.0);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for EchoVote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: EchoVote(author {}, epoch {},  height {})",
            self.digest(),
            self.author,
            self.epoch,
            self.height,
        )
    }
}

impl fmt::Display for EchoVote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: EchoVote(author {}, epoch {},  height {})",
            self.digest(),
            self.author,
            self.epoch,
            self.height,
        )
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct ReadyVote {
    pub author: PublicKey,
    pub epoch: SeqNumber,
    pub height: SeqNumber,
    pub digest: Digest,
    pub signature: Signature,
}

impl ReadyVote {
    pub async fn new(
        author: PublicKey,
        epoch: SeqNumber,
        height: SeqNumber,
        digest: Digest,
        mut signature_service: SignatureService,
    ) -> Self {
        let mut vote = Self {
            author,
            epoch,
            height,
            digest,
            signature: Signature::default(),
        };
        vote.signature = signature_service.request_signature(vote.digest()).await;
        return vote;
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(
            voting_rights > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature.verify(&self.digest(), &self.author)?;

        Ok(())
    }

    pub fn rank(&self, committee: &Committee) -> usize {
        let r = (self.epoch as usize) * committee.size() + (self.height as usize);
        r
    }
}

impl Hash for ReadyVote {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.digest.0);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for ReadyVote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: ReadyVote(author {}, epoch {},  height {})",
            self.digest(),
            self.author,
            self.epoch,
            self.height,
        )
    }
}

impl fmt::Display for ReadyVote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: ReadyVote(author {}, epoch {},  height {})",
            self.digest(),
            self.author,
            self.epoch,
            self.height,
        )
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct RBCProof {
    pub epoch: SeqNumber,
    pub height: SeqNumber,
    pub votes: Vec<(PublicKey, Signature)>,
    pub tag: u8,
}

impl RBCProof {
    pub fn new(
        epoch: SeqNumber,
        height: SeqNumber,
        votes: Vec<(PublicKey, Signature)>,
        tag: u8,
    ) -> Self {
        Self {
            epoch,
            height,
            votes,
            tag,
        }
    }

    // pub fn rank(&self, committee: &Committee) -> usize {
    //     let r =
    //         ((self.epoch as usize) * committee.size() + (self.height as usize)) % MAX_BLOCK_BUFFER;
    //     r
    // }
}

impl fmt::Debug for RBCProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "RBCProof(epoch {}, height {},tag {})",
            self.epoch, self.height, self.tag,
        )
    }
}

impl fmt::Display for RBCProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "RBCProof(epoch {},  height {},tag {})",
            self.epoch, self.height, self.tag,
        )
    }
}

/************************** RBC Struct ************************************/

/************************** SMVBA Struct ************************************/
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct SMVBAProposal {
    pub author: PublicKey,
    pub epoch: SeqNumber,
    pub height: SeqNumber,
    pub round: SeqNumber, //SMVBA 的轮数
    pub phase: u8,        //SPB 的阶段（VAL，AUX）
    pub vals: Vec<bool>,
    pub proof: SMVBAProof,
    pub signature: Signature,
}

impl SMVBAProposal {
    pub async fn new(
        author: PublicKey,
        epoch: SeqNumber,
        height: SeqNumber,
        round: SeqNumber,
        phase: u8,
        vals: Vec<bool>,
        proof: SMVBAProof,
        mut signature_service: SignatureService,
    ) -> Self {
        let mut proposal = Self {
            author,
            epoch,
            height,
            round,
            phase,
            vals,
            proof,
            signature: Signature::default(),
        };
        proposal.signature = signature_service.request_signature(proposal.digest()).await;
        return proposal;
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(
            voting_rights > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature.verify(&self.digest(), &self.author)?;

        Ok(())
    }
}

impl Hash for SMVBAProposal {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.round.to_le_bytes());
        hasher.update(self.phase.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for SMVBAProposal {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "SMVBAProposal(epoch {}, height {},round {})",
            self.epoch, self.height, self.round,
        )
    }
}

impl fmt::Display for SMVBAProposal {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "SMVBAProposal(epoch {},  height {},round {})",
            self.epoch, self.height, self.round,
        )
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct SMVBAVote {
    pub author: PublicKey,
    pub proposer: PublicKey,
    pub epoch: SeqNumber,
    pub height: SeqNumber,
    pub round: SeqNumber, //SMVBA 的轮数
    pub phase: u8,        //SPB 的阶段（VAL，AUX）
    pub digest: Digest,   //Proposal的hash
    pub signature: Signature,
}

impl SMVBAVote {
    pub async fn new(
        author: PublicKey,
        proposal: &SMVBAProposal,
        mut signature_service: SignatureService,
    ) -> Self {
        let mut vote = Self {
            author,
            proposer: proposal.author,
            epoch: proposal.epoch,
            height: proposal.height,
            round: proposal.round,
            phase: proposal.phase,
            digest: proposal.digest(),
            signature: Signature::default(),
        };
        vote.signature = signature_service.request_signature(vote.digest()).await;
        return vote;
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(
            voting_rights > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature.verify(&self.digest(), &self.author)?;

        Ok(())
    }
}

impl Hash for SMVBAVote {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.round.to_le_bytes());
        hasher.update(self.phase.to_le_bytes());
        hasher.update(self.digest.0);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for SMVBAVote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "SMVBAVote(epoch {}, height {},round {},phase {})",
            self.epoch, self.height, self.round, self.phase
        )
    }
}

impl fmt::Display for SMVBAVote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "SMVBAVote(epoch {}, height {},round {},phase {})",
            self.epoch, self.height, self.round, self.phase,
        )
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct SMVBAProof {
    pub proposer: PublicKey,
    pub epoch: SeqNumber,
    pub height: SeqNumber,
    pub round: SeqNumber,
    pub votes: Vec<SMVBAVote>,
    pub phase: u8,
}

impl SMVBAProof {
    pub fn new(
        proposer: PublicKey,
        epoch: SeqNumber,
        height: SeqNumber,
        round: SeqNumber,
        phase: u8,
    ) -> Self {
        Self {
            proposer,
            epoch,
            height,
            round,
            votes: Vec::new(),
            phase,
        }
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.proposer);
        ensure!(
            voting_rights > 0,
            ConsensusError::UnknownAuthority(self.proposer)
        );

        // Check the signature.
        for vote in &self.votes {
            vote.verify(committee)?;
        }

        Ok(())
    }
}

impl fmt::Debug for SMVBAProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "SMVBAProof(epoch {}, height {},round {},phase {})",
            self.epoch, self.height, self.round, self.phase
        )
    }
}

impl fmt::Display for SMVBAProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "SMVBAProof(epoch {}, height {},round {},phase {})",
            self.epoch, self.height, self.round, self.phase,
        )
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct SMVBAFinish {
    pub author: PublicKey,
    pub epoch: SeqNumber,
    pub height: SeqNumber,
    pub round: SeqNumber, //SMVBA 的轮数
    pub proof: SMVBAProof,
    pub signature: Signature,
}

impl SMVBAFinish {
    pub async fn new(
        author: PublicKey,
        epoch: SeqNumber,
        height: SeqNumber,
        round: SeqNumber,
        proof: SMVBAProof,
        mut signature_service: SignatureService,
    ) -> Self {
        let mut finish = Self {
            author,
            epoch,
            height,
            round,
            proof,
            signature: Signature::default(),
        };
        finish.signature = signature_service.request_signature(finish.digest()).await;
        return finish;
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(
            voting_rights > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature.verify(&self.digest(), &self.author)?;

        Ok(())
    }
}

impl Hash for SMVBAFinish {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.round.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for SMVBAFinish {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "SMVBAFinish(epoch {}, height {},round {})",
            self.epoch, self.height, self.round
        )
    }
}

impl fmt::Display for SMVBAFinish {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "SMVBAFinish(epoch {}, height {},round {})",
            self.epoch, self.height, self.round
        )
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct SMVBADone {
    pub author: PublicKey,
    pub epoch: SeqNumber,
    pub height: SeqNumber,
    pub round: SeqNumber, //SMVBA 的轮数
    pub signature: Signature,
}

impl SMVBADone {
    pub async fn new(
        author: PublicKey,
        epoch: SeqNumber,
        height: SeqNumber,
        round: SeqNumber,
        mut signature_service: SignatureService,
    ) -> Self {
        let mut done = Self {
            author,
            epoch,
            height,
            round,
            signature: Signature::default(),
        };
        done.signature = signature_service.request_signature(done.digest()).await;
        return done;
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(
            voting_rights > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature.verify(&self.digest(), &self.author)?;

        Ok(())
    }
}

impl Hash for SMVBADone {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.round.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for SMVBADone {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "SMVBADone(epoch {}, height {},round {})",
            self.epoch, self.height, self.round
        )
    }
}

impl fmt::Display for SMVBADone {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "SMVBADone(epoch {}, height {},round {})",
            self.epoch, self.height, self.round
        )
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct SMVBALockVote {
    author: PublicKey,
    proposer: PublicKey,
    epoch: SeqNumber,
    height: SeqNumber,
    round: SeqNumber,
    proof: SMVBAProof,
    tag: u8,
    signature: Signature,
}

impl SMVBALockVote {
    pub async fn new(
        author: PublicKey,
        proposer: PublicKey,
        epoch: SeqNumber,
        height: SeqNumber,
        round: SeqNumber,
        proof: SMVBAProof,
        tag: u8,
        mut siganture_service: SignatureService,
    ) -> Self {
        let mut lock = Self {
            author,
            proposer,
            epoch,
            height,
            round,
            proof,
            tag,
            signature: Signature::default(),
        };
        lock.signature = siganture_service.request_signature(lock.digest()).await;
        return lock;
    }

    pub fn verify(&self, committee: Committee) -> ConsensusResult<()> {
        let voting_rights = committee.stake(&self.author);
        ensure!(
            voting_rights > 0,
            ConsensusError::UnknownAuthority(self.author)
        );
        if self.tag == OPT {
            ensure!(
                self.proposer == self.proof.proposer && self.proof.phase == LOCK_PHASE,
                ConsensusError::SMVBANotFormLeader(self.proposer)
            )
        }

        // Check the signature.
        self.signature.verify(&self.digest(), &self.author)?;
        self.proof.verify(&committee)?;
        Ok(())
    }
}

impl Hash for SMVBALockVote {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.proposer.0);
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.round.to_le_bytes());
        hasher.update(self.tag.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for SMVBALockVote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "SMVBALockVote(epoch {}, height {},round {},tag {})",
            self.epoch, self.height, self.round, self.tag
        )
    }
}

impl fmt::Display for SMVBALockVote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "SMVBALockVote(epoch {}, height {},round {},tag {})",
            self.epoch, self.height, self.round, self.tag
        )
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct SMVBAFinVote {
    author: PublicKey,
    proposer: PublicKey,
    epoch: SeqNumber,
    height: SeqNumber,
    round: SeqNumber,
    proof: SMVBAProof,
    tag: u8,
    signature: Signature,
}

impl SMVBAFinVote {
    pub async fn new(
        author: PublicKey,
        proposer: PublicKey,
        epoch: SeqNumber,
        height: SeqNumber,
        round: SeqNumber,
        proof: SMVBAProof,
        tag: u8,
        mut siganture_service: SignatureService,
    ) -> Self {
        let mut lock = Self {
            author,
            proposer,
            epoch,
            height,
            round,
            proof,
            tag,
            signature: Signature::default(),
        };
        lock.signature = siganture_service.request_signature(lock.digest()).await;
        return lock;
    }

    pub fn verify(&self, committee: Committee) -> ConsensusResult<()> {
        let voting_rights = committee.stake(&self.author);
        ensure!(
            voting_rights > 0,
            ConsensusError::UnknownAuthority(self.author)
        );
        if self.tag == OPT {
            ensure!(
                self.proposer == self.proof.proposer && self.proof.phase == FINISH_PHASE,
                ConsensusError::SMVBANotFormLeader(self.proposer)
            )
        }

        // Check the signature.
        self.signature.verify(&self.digest(), &self.author)?;
        self.proof.verify(&committee)?;
        Ok(())
    }
}

impl Hash for SMVBAFinVote {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.proposer.0);
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.round.to_le_bytes());
        hasher.update(self.tag.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for SMVBAFinVote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "SMVBAFinVote(epoch {}, height {},round {},tag {})",
            self.epoch, self.height, self.round, self.tag
        )
    }
}

impl fmt::Display for SMVBAFinVote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "SMVBAFinVote(epoch {}, height {},round {},tag {})",
            self.epoch, self.height, self.round, self.tag
        )
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct SMVBAHalt {
    author: PublicKey,
    leader: PublicKey,
    epoch: SeqNumber,
    height: SeqNumber,
    round: SeqNumber,
    proof: SMVBAProof,
    signature: Signature,
}

impl SMVBAHalt {
    pub async fn new(
        author: PublicKey,
        leader: PublicKey,
        epoch: SeqNumber,
        height: SeqNumber,
        round: SeqNumber,
        proof: SMVBAProof,
        mut siganture_service: SignatureService,
    ) -> Self {
        let mut lock = Self {
            author,
            leader,
            epoch,
            height,
            round,
            proof,
            signature: Signature::default(),
        };
        lock.signature = siganture_service.request_signature(lock.digest()).await;
        return lock;
    }

    pub fn verify(&self, committee: Committee) -> ConsensusResult<()> {
        let voting_rights = committee.stake(&self.author);
        ensure!(
            voting_rights > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        ensure!(
            self.leader == self.proof.proposer && self.proof.phase == FINISH_PHASE,
            ConsensusError::SMVBANotFormLeader(self.leader)
        );

        // Check the signature.
        self.signature.verify(&self.digest(), &self.author)?;
        self.proof.verify(&committee)?;
        Ok(())
    }
}

impl Hash for SMVBAHalt {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.leader.0);
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.round.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for SMVBAHalt {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "SMVBAHalt(epoch {}, height {},round {},leader {})",
            self.epoch, self.height, self.round, self.leader
        )
    }
}

impl fmt::Display for SMVBAHalt {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "SMVBAHalt(epoch {}, height {},round {},leader {})",
            self.epoch, self.height, self.round, self.leader
        )
    }
}

/************************** SMVBA Struct ************************************/

/************************** ABA Struct ************************************/
// #[derive(Clone, Serialize, Deserialize)]
// pub struct ABAVal {
//     pub author: PublicKey,
//     pub epoch: SeqNumber,
//     pub height: SeqNumber,
//     pub round: SeqNumber, //ABA 的轮数
//     pub phase: u8,        //ABA 的阶段（VAL，AUX）
//     pub val: usize,
//     pub signature: Signature,
// }

// impl ABAVal {
//     pub async fn new(
//         author: PublicKey,
//         epoch: SeqNumber,
//         height: SeqNumber,
//         round: SeqNumber,
//         val: usize,
//         phase: u8,
//         mut signature_service: SignatureService,
//     ) -> Self {
//         let mut aba_val = Self {
//             author,
//             epoch,
//             height,
//             round,
//             val,
//             phase,
//             signature: Signature::default(),
//         };
//         aba_val.signature = signature_service.request_signature(aba_val.digest()).await;
//         return aba_val;
//     }

//     pub fn verify(&self) -> ConsensusResult<()> {
//         self.signature.verify(&self.digest(), &self.author)?;
//         Ok(())
//     }

//     pub fn rank(&self, committee: &Committee) -> usize {
//         let r = (self.epoch as usize) * committee.size() + (self.height as usize);
//         r
//     }
// }

// impl Hash for ABAVal {
//     fn digest(&self) -> Digest {
//         let mut hasher = Sha512::new();
//         hasher.update(self.author.0);
//         hasher.update(self.height.to_le_bytes());
//         hasher.update(self.epoch.to_le_bytes());
//         hasher.update(self.round.to_le_bytes());
//         Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
//     }
// }

// impl fmt::Debug for ABAVal {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         write!(
//             f,
//             "ABAVal(author{},epoch {},height {},round {},phase {},val {})",
//             self.author, self.epoch, self.height, self.round, self.phase, self.val
//         )
//     }
// }

// impl fmt::Display for ABAVal {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         write!(
//             f,
//             "ABAVal(author{},epoch {},height {},round {},phase {},val {})",
//             self.author, self.epoch, self.height, self.round, self.phase, self.val
//         )
//     }
// }

// #[derive(Clone, Serialize, Deserialize)]
// pub struct ABAOutput {
//     pub author: PublicKey,
//     pub epoch: SeqNumber,
//     pub height: SeqNumber,
//     pub round: SeqNumber,
//     pub val: usize,
//     pub signature: Signature,
// }

// impl ABAOutput {
//     pub async fn new(
//         author: PublicKey,
//         epoch: SeqNumber,
//         height: SeqNumber,
//         round: SeqNumber,
//         val: usize,
//         mut signature_service: SignatureService,
//     ) -> Self {
//         let mut out = Self {
//             author,
//             epoch,
//             height,
//             round,
//             val,
//             signature: Signature::default(),
//         };
//         out.signature = signature_service.request_signature(out.digest()).await;
//         return out;
//     }

//     pub fn verify(&self) -> ConsensusResult<()> {
//         self.signature.verify(&self.digest(), &self.author)?;
//         Ok(())
//     }

//     pub fn rank(&self, committee: &Committee) -> usize {
//         let r = (self.epoch as usize) * committee.size() + (self.height as usize);
//         r
//     }
// }

// impl Hash for ABAOutput {
//     fn digest(&self) -> Digest {
//         let mut hasher = Sha512::new();
//         hasher.update(self.author.0);
//         hasher.update(self.epoch.to_le_bytes());
//         hasher.update(self.height.to_le_bytes());
//         hasher.update(self.round.to_le_bytes());
//         Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
//     }
// }

// impl fmt::Debug for ABAOutput {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         write!(
//             f,
//             "ABAOutput(author {},epoch {},height {},round {},val {})",
//             self.author, self.epoch, self.height, self.round, self.val
//         )
//     }
// }

/************************** ABA Struct ************************************/

/************************** Share Coin Struct ************************************/
#[derive(Clone, Serialize, Deserialize)]
pub struct RandomnessShare {
    pub epoch: SeqNumber,
    pub height: SeqNumber,
    pub round: SeqNumber,
    pub author: PublicKey,
    pub signature_share: SignatureShare,
}

impl RandomnessShare {
    pub async fn new(
        epoch: SeqNumber,
        height: SeqNumber,
        round: SeqNumber,
        author: PublicKey,
        mut signature_service: SignatureService,
    ) -> Self {
        let mut hasher = Sha512::new();
        hasher.update(round.to_le_bytes());
        hasher.update(height.to_le_bytes());
        hasher.update(epoch.to_le_bytes());
        let digest = Digest(hasher.finalize().as_slice()[..32].try_into().unwrap());
        let signature_share = signature_service
            .request_tss_signature(digest)
            .await
            .unwrap();
        Self {
            round,
            height,
            epoch,
            author,
            signature_share,
        }
    }

    pub fn verify(&self, committee: &Committee, pk_set: &PublicKeySet) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            ConsensusError::UnknownAuthority(self.author)
        );
        let tss_pk = pk_set.public_key_share(committee.id(self.author));
        // Check the signature.
        ensure!(
            tss_pk.verify(&self.signature_share, &self.digest()),
            ConsensusError::InvalidThresholdSignature(self.author)
        );

        Ok(())
    }
}

impl Hash for RandomnessShare {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.round.to_le_bytes());
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.epoch.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for RandomnessShare {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "RandomnessShare (author {}, height {},round {})",
            self.author, self.height, self.round,
        )
    }
}
/************************** Share Coin Struct **************************/
