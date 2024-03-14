use std::collections::{HashMap, HashSet};
use std::process::Output;

use crate::aggregator::Aggregator;
use crate::config::{Committee, Parameters, Stake};
use crate::error::{ConsensusError, ConsensusResult};
use crate::filter::FilterInput;
use crate::mempool::MempoolDriver;
use crate::messages::{
    Block, EchoVote, RBCProof, RandomnessShare, ReadyVote, SMVBADone, SMVBAFinVote, SMVBAFinish,
    SMVBAHalt, SMVBALockVote, SMVBAProof, SMVBAProposal, SMVBAVote,
};
use crate::synchronizer::Synchronizer;
use async_recursion::async_recursion;
use crypto::{Digest, PublicKey, SignatureService};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use store::Store;
use threshold_crypto::PublicKeySet;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep, Duration};
#[cfg(test)]
#[path = "tests/core_tests.rs"]
pub mod core_tests;

pub type SeqNumber = u64; // For both round and view
pub type HeightNumber = u8; // height={1,2} in fallback chain, height=0 for sync block

pub const RBC_ECHO: u8 = 0;
pub const RBC_READY: u8 = 1;

pub const VAL_PHASE: u8 = 0;
pub const MUX_PHASE: u8 = 1;

pub const LOCK_PHASE: u8 = 0;
pub const FINISH_PHASE: u8 = 1;

pub const OPT: u8 = 0;
pub const PES: u8 = 1;

#[derive(Serialize, Deserialize, Debug)]
pub enum ConsensusMessage {
    RBCValMsg(Block),
    RBCEchoMsg(EchoVote),
    RBCReadyMsg(ReadyVote),
    MVBAProposeMsg(SMVBAProposal),
    MVBAVoteMsg(SMVBAVote),
    MVBAFinishMsg(SMVBAFinish),
    MVBADoneAndShareMsg(SMVBADone, RandomnessShare),
    MVBALockVoteMsg(SMVBALockVote),
    MVBAFinishVoteMsg(SMVBAFinVote),
    MVBAHaltMsg(SMVBAHalt),
    LoopBackMsg(SeqNumber, SeqNumber),
    SyncRequestMsg(SeqNumber, SeqNumber, PublicKey),
    SyncReplyMsg(Block),
}

pub struct Core {
    name: PublicKey,
    committee: Committee,
    parameters: Parameters,
    store: Store,
    signature_service: SignatureService,
    pk_set: PublicKeySet,
    mempool_driver: MempoolDriver,
    synchronizer: Synchronizer,
    _tx_core: Sender<ConsensusMessage>,
    rx_core: Receiver<ConsensusMessage>,
    network_filter: Sender<FilterInput>,
    _commit_channel: Sender<Block>,
    epoch: SeqNumber,
    height: SeqNumber,
    aggregator: Aggregator,
    rbc_proofs: HashMap<(SeqNumber, SeqNumber, u8), RBCProof>, //需要update
    rbc_ready: HashSet<(SeqNumber, SeqNumber)>,
    rbc_epoch_outputs: HashMap<SeqNumber, HashSet<SeqNumber>>,
    smvba_invoke: HashSet<SeqNumber>,
    smvba_proposal: HashMap<(SeqNumber, SeqNumber), Vec<bool>>,
    smvba_lock_proof: HashMap<(SeqNumber, PublicKey, SeqNumber), SMVBAProof>,
    smvba_finish_proof: HashMap<(SeqNumber, PublicKey, SeqNumber), SMVBAProof>,
    smvba_finish: HashMap<(SeqNumber, SeqNumber), HashSet<SeqNumber>>,
    smvba_done: HashMap<(SeqNumber, SeqNumber), HashSet<SeqNumber>>,
    smvba_send_done: HashSet<(SeqNumber, SeqNumber)>,
    smvba_leader: HashMap<(SeqNumber, SeqNumber), Option<PublicKey>>,
}

impl Core {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: PublicKey,
        committee: Committee,
        parameters: Parameters,
        signature_service: SignatureService,
        pk_set: PublicKeySet,
        store: Store,
        mempool_driver: MempoolDriver,
        synchronizer: Synchronizer,
        tx_core: Sender<ConsensusMessage>,
        rx_core: Receiver<ConsensusMessage>,
        network_filter: Sender<FilterInput>,
        commit_channel: Sender<Block>,
    ) -> Self {
        let aggregator = Aggregator::new(committee.clone());
        Self {
            epoch: 0,
            height: committee.id(name) as u64,
            name,
            committee,
            parameters,
            signature_service,
            pk_set,
            store,
            mempool_driver,
            synchronizer,
            network_filter,
            _commit_channel: commit_channel,
            _tx_core: tx_core,
            rx_core,
            aggregator,
            rbc_proofs: HashMap::new(),
            rbc_ready: HashSet::new(),
            rbc_epoch_outputs: HashMap::new(),
            smvba_invoke: HashSet::new(),
            smvba_proposal: HashMap::new(),
            smvba_lock_proof: HashMap::new(),
            smvba_finish_proof: HashMap::new(),
            smvba_finish: HashMap::new(),
            smvba_done: HashMap::new(),
            smvba_send_done: HashSet::new(),
            smvba_leader: HashMap::new(),
        }
    }

    pub fn rank(epoch: SeqNumber, height: SeqNumber, committee: &Committee) -> usize {
        let r = (epoch as usize) * committee.size() + (height as usize);
        r
    }

    async fn store_block(&mut self, block: &Block) {
        let key: Vec<u8> = block.rank(&self.committee).to_le_bytes().into();
        let value = bincode::serialize(block).expect("Failed to serialize block");
        self.store.write(key, value).await;
    }

    async fn commit(&mut self, blocks: Vec<Block>) -> ConsensusResult<()> {
        if blocks.len() > 0 {
            let epoch = blocks[0].epoch;
            let mut digest: Vec<Digest> = Vec::new();
            for block in blocks {
                if !block.payload.is_empty() {
                    info!("Committed {}", block);

                    #[cfg(feature = "benchmark")]
                    for x in &block.payload {
                        info!(
                            "Committed B{}({}) epoch {}",
                            block.height,
                            base64::encode(x),
                            block.epoch,
                        );
                    }
                }
                digest.append(&mut block.payload.clone());
                debug!("Committed {}", block);
            }
            self.cleanup(digest, epoch).await?;
        }
        Ok(())
    }

    async fn cleanup(&mut self, digest: Vec<Digest>, epoch: SeqNumber) -> ConsensusResult<()> {
        self.aggregator.cleanup(epoch);
        self.mempool_driver
            .cleanup(digest, epoch, (self.committee.size() - 1) as SeqNumber)
            .await;
        self.rbc_proofs.retain(|(e, ..), _| *e > epoch);
        self.rbc_ready.retain(|(e, ..)| *e > epoch);
        // self.rbc_outputs.retain(|(e, h, ..), _| e * size + h > rank);
        // self.prepare_flags.retain(|(e, h), _| e * size + h > rank);
        Ok(())
    }

    /************* RBC Protocol ******************/
    #[async_recursion]
    async fn generate_rbc_proposal(&mut self) -> ConsensusResult<Block> {
        // Make a new block.
        debug!("start rbc epoch {}", self.epoch);
        let payload = self
            .mempool_driver
            .get(self.parameters.max_payload_size)
            .await;
        let block = Block::new(
            self.name,
            self.epoch,
            self.height,
            payload,
            self.signature_service.clone(),
        )
        .await;
        if !block.payload.is_empty() {
            info!("Created {}", block);

            #[cfg(feature = "benchmark")]
            for x in &block.payload {
                // NOTE: This log entry is used to compute performance.
                info!(
                    "Created B{}({}) epoch {}",
                    block.height,
                    base64::encode(x),
                    block.epoch
                );
            }
        }
        debug!("Created {:?}", block);

        // Process our new block and broadcast it.
        let message = ConsensusMessage::RBCValMsg(block.clone());
        Synchronizer::transmit(
            message,
            &self.name,
            None,
            &self.network_filter,
            &self.committee,
        )
        .await?;
        self.handle_rbc_val(&block).await?;

        // Wait for the minimum block delay.
        sleep(Duration::from_millis(self.parameters.min_block_delay)).await;

        Ok(block)
    }

    async fn handle_rbc_val(&mut self, block: &Block) -> ConsensusResult<()> {
        debug!(
            "processing RBC val epoch {} height {}",
            block.epoch, block.height
        );
        block.verify(&self.committee)?;
        self.store_block(block).await;

        let vote = EchoVote::new(
            self.name,
            block.epoch,
            block.height,
            block,
            self.signature_service.clone(),
        )
        .await;
        let message = ConsensusMessage::RBCEchoMsg(vote.clone());

        Synchronizer::transmit(
            message,
            &self.name,
            None,
            &self.network_filter,
            &self.committee,
        )
        .await?;

        self.handle_rbc_echo(&vote).await?;
        Ok(())
    }

    async fn handle_rbc_echo(&mut self, vote: &EchoVote) -> ConsensusResult<()> {
        debug!(
            "processing RBC echo_vote epoch {} height {}",
            vote.epoch, vote.height
        );
        vote.verify(&self.committee)?;

        if let Some(proof) = self.aggregator.add_rbc_echo_vote(vote)? {
            self.rbc_proofs
                .insert((proof.epoch, proof.height, proof.tag), proof);
            self.rbc_ready.insert((vote.epoch, vote.height));
            let ready = ReadyVote::new(
                self.name,
                vote.epoch,
                vote.height,
                vote.digest.clone(),
                self.signature_service.clone(),
            )
            .await;
            let message = ConsensusMessage::RBCReadyMsg(ready.clone());
            Synchronizer::transmit(
                message,
                &self.name,
                None,
                &self.network_filter,
                &self.committee,
            )
            .await?;
            self.handle_rbc_ready(&ready).await?;
        }

        Ok(())
    }

    #[async_recursion]
    async fn handle_rbc_ready(&mut self, vote: &ReadyVote) -> ConsensusResult<()> {
        debug!(
            "processing RBC ready_vote epoch {} height {}",
            vote.epoch, vote.height
        );
        vote.verify(&self.committee)?;

        if let Some(proof) = self.aggregator.add_rbc_ready_vote(vote)? {
            let flag = self.rbc_ready.contains(&(vote.epoch, vote.height));

            self.rbc_proofs
                .insert((proof.epoch, proof.height, proof.tag), proof.clone());

            if !flag && proof.votes.len() as Stake == self.committee.random_coin_threshold() {
                self.rbc_ready.insert((vote.epoch, vote.height));
                let ready = ReadyVote::new(
                    self.name,
                    vote.epoch,
                    vote.height,
                    vote.digest.clone(),
                    self.signature_service.clone(),
                )
                .await;
                let message = ConsensusMessage::RBCReadyMsg(ready.clone());
                Synchronizer::transmit(
                    message,
                    &self.name,
                    None,
                    &self.network_filter,
                    &self.committee,
                )
                .await?;
                self.handle_rbc_ready(&ready).await?;
                return Ok(());
            }
            if proof.votes.len() as Stake == self.committee.quorum_threshold() {
                self.process_rbc_output(vote.epoch, vote.height).await?;
            }
        }

        Ok(())
    }

    #[async_recursion]
    async fn process_rbc_output(
        &mut self,
        epoch: SeqNumber,
        height: SeqNumber,
    ) -> ConsensusResult<()> {
        debug!("processing RBC output epoch {} height {}", epoch, height);
        let outputs = self
            .rbc_epoch_outputs
            .entry(epoch)
            .or_insert(HashSet::new());
        if outputs.insert(height) {
            if outputs.len() as Stake == self.committee.quorum_threshold() {
                let mut vals = Vec::new();
                for height in 0..(self.committee.size() as SeqNumber) {
                    if outputs.contains(&height) {
                        vals.push(true);
                    } else {
                        vals.push(false);
                    }
                }
                self.invoke_mvba(epoch, self.height, vals).await?;
            }
        }
        Ok(())
    }

    async fn handle_sync_request(
        &mut self,
        epoch: SeqNumber,
        height: SeqNumber,
        sender: PublicKey,
    ) -> ConsensusResult<()> {
        debug!("processing sync request epoch {} height {}", epoch, height);
        let rank = Core::rank(epoch, height, &self.committee);
        if let Some(bytes) = self.store.read(rank.to_le_bytes().into()).await? {
            let block = bincode::deserialize(&bytes)?;
            let message = ConsensusMessage::SyncReplyMsg(block);
            Synchronizer::transmit(
                message,
                &self.name,
                Some(&sender),
                &self.network_filter,
                &self.committee,
            )
            .await?;
        }
        Ok(())
    }

    async fn handle_sync_reply(&mut self, block: &Block) -> ConsensusResult<()> {
        debug!(
            "processing sync reply epoch {} height {}",
            block.epoch, block.height
        );
        block.verify(&self.committee)?;
        self.store_block(block).await;
        self.process_rbc_output(block.epoch, block.height).await?;
        Ok(())
    }
    /************* RBC Protocol ******************/

    /************* SMVBA Protocol ******************/
    async fn invoke_mvba(
        &mut self,
        epoch: SeqNumber,
        height: SeqNumber,
        vals: Vec<bool>,
    ) -> ConsensusResult<()> {
        if self.smvba_invoke.insert(epoch) {
            let proposal = SMVBAProposal::new(
                self.name,
                epoch,
                height,
                0,
                LOCK_PHASE,
                vals,
                SMVBAProof::default(),
                self.signature_service.clone(),
            )
            .await;
            let message = ConsensusMessage::MVBAProposeMsg(proposal.clone());
            Synchronizer::transmit(
                message,
                &self.name,
                None,
                &self.network_filter,
                &self.committee,
            )
            .await?;
            self.handle_mvba_proposal(&proposal).await?;
        }
        Ok(())
    }

    async fn handle_mvba_proposal(&mut self, proposal: &SMVBAProposal) -> ConsensusResult<()> {
        debug!("Processing {}", proposal);
        proposal.verify(&self.committee)?;
        if proposal.phase == LOCK_PHASE {
            self.smvba_proposal
                .insert((proposal.epoch, proposal.height), proposal.vals.clone());
        }
        if proposal.phase == FINISH_PHASE {
            self.smvba_lock_proof.insert(
                (proposal.epoch, proposal.author, proposal.round),
                proposal.proof.clone(),
            );
        }
        let vote = SMVBAVote::new(self.name, proposal, self.signature_service.clone()).await;
        if self.name == proposal.author {
            self.handle_mvba_pbvote(&vote).await?;
        } else {
            let message = ConsensusMessage::MVBAVoteMsg(vote);
            Synchronizer::transmit(
                message,
                &self.name,
                Some(&proposal.author),
                &self.network_filter,
                &self.committee,
            )
            .await?;
        }
        Ok(())
    }

    #[async_recursion]
    async fn handle_mvba_pbvote(&mut self, vote: &SMVBAVote) -> ConsensusResult<()> {
        debug!("Procesing {}", vote);
        vote.verify(&self.committee)?;
        if let Some(proof) = self.aggregator.add_smvba_spb_vote(vote)? {
            if proof.phase == LOCK_PHASE {
                self.smvba_lock_proof
                    .insert((proof.epoch, proof.proposer, proof.round), proof.clone());
                let proposal = SMVBAProposal::new(
                    self.name,
                    proof.epoch,
                    self.height,
                    proof.round,
                    FINISH_PHASE,
                    vec![],
                    proof,
                    self.signature_service.clone(),
                )
                .await;
                let message = ConsensusMessage::MVBAProposeMsg(proposal.clone());
                Synchronizer::transmit(
                    message,
                    &self.name,
                    None,
                    &self.network_filter,
                    &self.committee,
                )
                .await?;
                self.handle_mvba_proposal(&proposal).await?;
            } else {
                self.smvba_finish_proof
                    .insert((proof.epoch, proof.proposer, proof.round), proof.clone());
                let finish = SMVBAFinish::new(
                    self.name,
                    proof.epoch,
                    self.height,
                    proof.round,
                    proof,
                    self.signature_service.clone(),
                )
                .await;
                let message = ConsensusMessage::MVBAFinishMsg(finish.clone());
                Synchronizer::transmit(
                    message,
                    &self.name,
                    None,
                    &self.network_filter,
                    &self.committee,
                )
                .await?;
                self.handle_mvba_finish(&finish).await?;
            }
        }
        Ok(())
    }

    async fn handle_mvba_finish(&mut self, finish: &SMVBAFinish) -> ConsensusResult<()> {
        debug!("Processing {}", finish);
        finish.verify(&self.committee)?;
        let set = self
            .smvba_finish
            .entry((finish.epoch, finish.round))
            .or_insert(HashSet::new());
        if set.insert(finish.height) {
            if set.len() as Stake == self.committee.quorum_threshold() {
                self.send_done_and_share(finish.epoch, finish.round).await?;
            }
        }
        Ok(())
    }

    async fn send_done_and_share(
        &mut self,
        epoch: SeqNumber,
        round: SeqNumber,
    ) -> ConsensusResult<()> {
        if !self.smvba_send_done.contains(&(epoch, round)) {
            let done = SMVBADone::new(
                self.name,
                epoch,
                self.height,
                round,
                self.signature_service.clone(),
            )
            .await;
            let share = RandomnessShare::new(
                epoch,
                self.height,
                round,
                self.name,
                self.signature_service.clone(),
            )
            .await;
            self.smvba_send_done.insert((epoch, round));
            let message = ConsensusMessage::MVBADoneAndShareMsg(done.clone(), share.clone());
            Synchronizer::transmit(
                message,
                &self.name,
                None,
                &self.network_filter,
                &self.committee,
            )
            .await?;
            self.hanlde_mvba_done_and_share(&done, &share).await?;
        }
        Ok(())
    }

    #[async_recursion]
    async fn hanlde_mvba_done_and_share(
        &mut self,
        done: &SMVBADone,
        share: &RandomnessShare,
    ) -> ConsensusResult<()> {
        self.handle_mvba_done(done).await?;
        self.handle_mvba_share_coin(share).await?;
        Ok(())
    }

    async fn handle_mvba_done(&mut self, done: &SMVBADone) -> ConsensusResult<()> {
        debug!("Processing {}", done);
        done.verify(&self.committee)?;
        let set = self
            .smvba_done
            .entry((done.epoch, done.round))
            .or_insert(HashSet::new());
        if set.insert(done.height) {
            if set.len() as Stake == self.committee.random_coin_threshold() {
                self.send_done_and_share(done.epoch, done.round).await?;
            }
        }
        Ok(())
    }

    async fn handle_mvba_share_coin(&mut self, share: &RandomnessShare) -> ConsensusResult<()> {
        debug!("Processing {:?}", share);
        share.verify(&self.committee, &self.pk_set)?;
        if let Some(leader) = self.aggregator.add_smvba_share_coin(share, &self.pk_set)? {
            self.smvba_leader
                .insert((share.epoch, share.round), Some(leader));
            if self
                .smvba_finish_proof
                .contains_key(&(share.epoch, leader, share.round))
            {
                let proof = self
                    .smvba_finish_proof
                    .entry((share.epoch, leader, share.round))
                    .or_default();
                let halt = SMVBAHalt::new(
                    self.name,
                    leader,
                    share.epoch,
                    self.height,
                    share.round,
                    proof.clone(),
                    self.signature_service.clone(),
                )
                .await;
                let message = ConsensusMessage::MVBAHaltMsg(halt.clone());
                Synchronizer::transmit(
                    message,
                    &self.name,
                    None,
                    &self.network_filter,
                    &self.committee,
                )
                .await?;
                self.handle_mvba_halt(&halt).await?;
            }
        }
        Ok(())
    }

    async fn handle_mvba_lock_vote(&mut self, vote: &SMVBALockVote) -> ConsensusResult<()> {
        Ok(())
    }

    async fn handle_mvba_finish_vote(&mut self, vote: &SMVBAFinVote) -> ConsensusResult<()> {
        Ok(())
    }

    async fn handle_mvba_halt(&mut self, halt: &SMVBAHalt) -> ConsensusResult<()> {
        Ok(())
    }
    /************* SMVBA Protocol ******************/

    // pub async fn handle_epoch_end(&mut self, epoch: SeqNumber) -> ConsensusResult<()> {
    //     let mut data: Vec<Block> = Vec::new();

    //     for height in 0..(self.committee.size() as SeqNumber) {
    //         if *self.aba_ends.get(&(epoch, height)).unwrap() == OPT {
    //             if let Some(block) = self
    //                 .synchronizer
    //                 .block_request(epoch, height, &self.committee)
    //                 .await?
    //             {
    //                 if !self.mempool_driver.verify(block.clone()).await? {
    //                     return Ok(());
    //                 }
    //                 data.push(block);
    //             }
    //         }
    //     }
    //     self.commit(data).await?;
    //     self.advance_epoch(epoch + 1).await?;
    //     Ok(())
    // }

    // pub async fn advance_epoch(&mut self, epoch: SeqNumber) -> ConsensusResult<()> {
    //     if epoch > self.epoch {
    //         self.epoch = epoch;
    //         self.generate_rbc_proposal().await?;
    //     }
    //     Ok(())
    // }

    pub async fn run(&mut self) {
        if let Err(e) = self.generate_rbc_proposal().await {
            panic!("protocol invoke failed! error {}", e);
        }
        loop {
            let result = tokio::select! {
                Some(message) = self.rx_core.recv() => {
                    match message {
                        ConsensusMessage::RBCValMsg(block)=> self.handle_rbc_val(&block).await,
                        ConsensusMessage::RBCEchoMsg(evote)=> self.handle_rbc_echo(&evote).await,
                        ConsensusMessage::RBCReadyMsg(rvote)=> self.handle_rbc_ready(&rvote).await,
                        ConsensusMessage::MVBAProposeMsg(proposal)=>self.handle_mvba_proposal(&proposal).await,
                        ConsensusMessage::MVBAVoteMsg(vote)=>self.handle_mvba_pbvote(&vote).await,
                        ConsensusMessage::MVBAFinishMsg(finish)=>self.handle_mvba_finish(&finish).await,
                        ConsensusMessage::MVBADoneAndShareMsg(done,share)=>self.hanlde_mvba_done_and_share(&done,&share).await,
                        ConsensusMessage::MVBALockVoteMsg(vote)=>self.handle_mvba_lock_vote(&vote).await,
                        ConsensusMessage::MVBAFinishVoteMsg(vote)=>self.handle_mvba_finish_vote(&vote).await,
                        ConsensusMessage::MVBAHaltMsg(halt)=>self.handle_mvba_halt(&halt).await,
                        ConsensusMessage::LoopBackMsg(epoch,height) => self.process_rbc_output(epoch,height).await,
                        ConsensusMessage::SyncRequestMsg(epoch,height, sender) => self.handle_sync_request(epoch,height, sender).await,
                        ConsensusMessage::SyncReplyMsg(block) => self.handle_sync_reply(&block).await,
                    }
                },

                else => break,
            };
            match result {
                Ok(()) => (),
                Err(ConsensusError::StoreError(e)) => error!("{}", e),
                Err(ConsensusError::SerializationError(e)) => error!("Store corrupted. {}", e),
                Err(e) => warn!("{}", e),
            }
        }
    }
}
