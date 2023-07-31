//! Types, traits, abstractions and utilities for authorized (i.e identity authenticated or quorum approved) key refresh.
//!
//! NOTE: Used by share addition, share removal, threshold modification and share recovery with quorum protocols.

use round_based::{IsCritical, Msg, StateMachine};
use wamu_core::IdentityProvider;

use crate::key_refresh::AugmentedKeyRefresh;
use crate::{IdentityAuthentication, QuorumApproval};

pub trait AuthorizedKeyRefresh<'a, I: IdentityProvider + 'a>: StateMachine {
    /// The type of the initialization `StateMachine`.
    type InitStateMachineType: StateMachine;

    /// Returns an immutable reference to the initialization state machine.
    fn init_state_machine(&self) -> &Self::InitStateMachineType;

    /// Returns a mutable reference to the initialization state machine.
    fn init_state_machine_mut(&mut self) -> &mut Self::InitStateMachineType;

    /// Returns an immutable reference to the initialization state machine.
    fn refresh_state_machine(&self) -> Option<&AugmentedKeyRefresh<'a, I>>;

    /// Returns a mutable reference to the initialization state machine.
    fn refresh_state_machine_mut(&mut self) -> Option<&mut AugmentedKeyRefresh<'a, I>>;

    /// Returns an immutable reference to the composite message queue.
    fn composite_message_queue(
        &self,
    ) -> &Vec<
        Msg<
            AuthorizedKeyRefreshMessage<
                'a,
                I,
                <Self::InitStateMachineType as StateMachine>::MessageBody,
            >,
        >,
    >;

    /// Returns a mutable reference to the composite message queue.
    fn composite_message_queue_mut(
        &mut self,
    ) -> &mut Vec<
        Msg<
            AuthorizedKeyRefreshMessage<
                'a,
                I,
                <Self::InitStateMachineType as StateMachine>::MessageBody,
            >,
        >,
    >;

    /// Initializes party for the key refresh protocol (if necessary).
    fn init_key_refresh(&mut self) -> Result<(), <Self as StateMachine>::Err>;

    /// Updates the composite message queue by
    /// retrieving the message queue from the currently active wrapped state machines (i.e initialization or key refresh).
    ///
    /// **NOTE:** This method is called at the end of both [`handle_incoming`](StateMachine::handle_incoming) and [`proceed`](StateMachine::proceed).
    fn update_composite_message_queue(&mut self) -> Result<(), <Self as StateMachine>::Err> {
        match self.refresh_state_machine_mut() {
            // Retrieves initialization phase messages.
            None => {
                let new_messages = self.init_state_machine_mut().message_queue().split_off(0);
                if !new_messages.is_empty() {
                    // Update composite message queue.
                    self.composite_message_queue_mut()
                        .extend(&mut new_messages.into_iter().map(|msg| {
                            msg.map_body(|msg_body| AuthorizedKeyRefreshMessage::Init(msg_body))
                        }));
                }
            }
            Some(refresh_state_machine) => {
                let new_messages = refresh_state_machine.message_queue().split_off(0);
                if !new_messages.is_empty() {
                    // Update composite message queue.
                    self.composite_message_queue_mut()
                        .extend(&mut new_messages.into_iter().map(|msg| {
                            msg.map_body(|msg_body| {
                                AuthorizedKeyRefreshMessage::Refresh(Box::new(msg_body))
                            })
                        }));
                }
            }
        }

        Ok(())
    }

    /// Transitions to the key refresh state machine if the initialization state machine is finished and the key refresh state machine is not yet active.
    ///
    /// **NOTE:** This method is called at the end of both [`handle_incoming`](StateMachine::handle_incoming) and [`proceed`](StateMachine::proceed).
    fn perform_transition(&mut self) -> Result<(), <Self as StateMachine>::Err> {
        if self.refresh_state_machine().is_none() && self.init_state_machine().is_finished() {
            self.init_key_refresh()?;
        }

        Ok(())
    }
}

#[derive(Clone)]
pub enum AuthorizedKeyRefreshMessage<'a, I: IdentityProvider, T> {
    Init(T),
    Refresh(Box<<AugmentedKeyRefresh<'a, I> as StateMachine>::MessageBody>),
}

#[derive(Debug)]
pub enum Error<'a, I: IdentityProvider, E> {
    Init(E),
    Refresh(<AugmentedKeyRefresh<'a, I> as StateMachine>::Err),
    AlreadyPicked,
    InvalidInput,
    OutOfOrderMessage,
}

impl<'a, I: IdentityProvider, E> IsCritical for Error<'a, I, E> {
    fn is_critical(&self) -> bool {
        true
    }
}

impl<'a, I: IdentityProvider, E> From<<AugmentedKeyRefresh<'a, I> as StateMachine>::Err>
    for Error<'a, I, E>
{
    fn from(error: <AugmentedKeyRefresh<'a, I> as StateMachine>::Err) -> Self {
        Self::Refresh(error)
    }
}

/// Implements `StateMachine` trait for types that implement `AuthorizedKeyRefresh`.
///
/// Requires the types of the `AugmentedStateMachine`, the wrapped `StateMachine`, additional parameters and additional output.
macro_rules! impl_state_machine_for_authorized_key_refresh {
    ($name:ident, $idx:ident, $n_parties:ident) => {
        impl<'a, I: IdentityProvider> StateMachine for $name<'a, I> {
            type MessageBody = AuthorizedKeyRefreshMessage<
                'a,
                I,
                <<Self as AuthorizedKeyRefresh<'a, I>>::InitStateMachineType as StateMachine>::MessageBody,
            >;
            type Err = Error<'a, I, <<Self as AuthorizedKeyRefresh<'a, I>>::InitStateMachineType as StateMachine>::Err>;
            type Output = <AugmentedKeyRefresh<'a, I> as StateMachine>::Output;

            fn handle_incoming(&mut self, msg: Msg<Self::MessageBody>) -> Result<(), Self::Err> {
                match msg.body {
                    // Initialization messages are forwarded to the initialization state machine if it's still active,
                    // otherwise an error is returned.
                    AuthorizedKeyRefreshMessage::Init(id_msg) => match self.refresh_state_machine() {
                        None => {
                            self.init_state_machine_mut().handle_incoming(Msg {
                                sender: msg.sender,
                                receiver: msg.receiver,
                                body: id_msg,
                            })?;
                        }
                        Some(_) => {
                            return Err(Error::OutOfOrderMessage);
                        }
                    },
                    // Refresh messages are forwarded to the refresh state machine if it's active,
                    // otherwise an error is returned.
                    AuthorizedKeyRefreshMessage::Refresh(refresh_msg) => {
                        match self.refresh_state_machine_mut() {
                            Some(refresh_state_machine) => {
                                refresh_state_machine.handle_incoming(Msg {
                                    sender: msg.sender,
                                    receiver: msg.receiver,
                                    body: *refresh_msg,
                                })?;
                            }
                            None => {
                                return Err(Error::OutOfOrderMessage);
                            }
                        }
                    }
                }

                // Updates the composite message queue.
                self.update_composite_message_queue()?;

                // Attempts to transition to the next state machine.
                self.perform_transition()
            }

            fn message_queue(&mut self) -> &mut Vec<Msg<Self::MessageBody>> {
                self.composite_message_queue_mut()
            }

            fn wants_to_proceed(&self) -> bool {
                // `wants_to_proceed` is forwarded to the active state machine.
                match self.refresh_state_machine() {
                    None => self.init_state_machine.wants_to_proceed(),
                    Some(refresh_state_machine) => refresh_state_machine.wants_to_proceed(),
                }
            }

            fn proceed(&mut self) -> Result<(), Self::Err> {
                // `proceed` is forwarded to the active state machine.
                match self.refresh_state_machine_mut() {
                    None => self.init_state_machine_mut().proceed()?,
                    Some(refresh_state_machine) => refresh_state_machine.proceed()?,
                }

                // Updates the composite message queue.
                self.update_composite_message_queue()?;

                // Attempts to transition to the next state machine.
                self.perform_transition()
            }

            fn round_timeout(&self) -> Option<Duration> {
                None
            }

            fn round_timeout_reached(&mut self) -> Self::Err {
                panic!("no timeout was set")
            }

            fn is_finished(&self) -> bool {
                // Is finished is true if both state machines are finished.
                self.init_state_machine().is_finished()
                    && self
                        .refresh_state_machine()
                        .map_or(false, |refresh_state_machine| {
                            refresh_state_machine.is_finished()
                        })
            }

            fn pick_output(&mut self) -> Option<Result<Self::Output, Self::Err>> {
                // Picks output from key refresh state machine (if possible).
                self.is_finished().then(|| {
                    self.refresh_state_machine_mut()
                        .and_then(|refresh_state_machine| refresh_state_machine.pick_output())
                        .map(|it| it.map_err(|error| Error::Refresh(error)))
                })?
            }

            fn current_round(&self) -> u16 {
                // Computes current round as an aggregate based on active state machine.
                match self.refresh_state_machine() {
                    None => self.init_state_machine().current_round(),
                    Some(refresh_state_machine) => {
                        self.init_state_machine().total_rounds().unwrap_or(0)
                            + refresh_state_machine.current_round()
                    }
                }
            }

            fn total_rounds(&self) -> Option<u16> {
                None
            }

            fn party_ind(&self) -> u16 {
                self.$idx
            }

            fn parties(&self) -> u16 {
                self.$n_parties
            }
        }
    };
}

/// Implements all required `AuthorizedKeyRefresh` getters.
///
/// Requires names of the associated fields
/// (.ie the initialization and key refresh `StateMachine` and the composite message queue).
macro_rules! impl_required_authorized_key_refresh_getters {
    ($init_state_machine:ident, $refresh_state_machine:ident, $message_queue:ident) => {
        fn init_state_machine(&self) -> &Self::InitStateMachineType {
            &self.$init_state_machine
        }

        fn init_state_machine_mut(&mut self) -> &mut Self::InitStateMachineType {
            &mut self.$init_state_machine
        }

        fn refresh_state_machine(&self) -> Option<&AugmentedKeyRefresh<'a, I>> {
            self.$refresh_state_machine.as_ref()
        }

        fn refresh_state_machine_mut(&mut self) -> Option<&mut AugmentedKeyRefresh<'a, I>> {
            self.$refresh_state_machine.as_mut()
        }

        fn composite_message_queue(
            &self,
        ) -> &Vec<
            Msg<
                AuthorizedKeyRefreshMessage<
                    'a,
                    I,
                    <Self::InitStateMachineType as StateMachine>::MessageBody,
                >,
            >,
        > {
            &self.$message_queue
        }

        fn composite_message_queue_mut(
            &mut self,
        ) -> &mut Vec<
            Msg<
                AuthorizedKeyRefreshMessage<
                    'a,
                    I,
                    <Self::InitStateMachineType as StateMachine>::MessageBody,
                >,
            >,
        > {
            self.$message_queue.as_mut()
        }
    };
}

/// Implements `From` trait for `StateMachine` associated error types.
macro_rules! from_state_machine_error {
    ($($state_machine_type:ident),*$(,)?) => {
        $(
        impl<'a, I: IdentityProvider> From<<$state_machine_type<'a, I> as StateMachine>::Err> for Error<'a, I, <$state_machine_type<'a, I> as StateMachine>::Err> {
            fn from(error: <$state_machine_type<'a, I> as StateMachine>::Err) -> Self {
                Self::Init(error)
            }
        }
        )*
    }
}

// Implements `From` trait for `IdentityAuthentication` and `QuorumApproval` state machine error types.
from_state_machine_error! {
    IdentityAuthentication,
    QuorumApproval,
}

// Implement `Debug` trait for `AuthorizedKeyRefreshMessage` for test simulations.
#[cfg(test)]
impl<'a, I: IdentityProvider, T> std::fmt::Debug for AuthorizedKeyRefreshMessage<'a, I, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Authorized Key Refresh Message")
    }
}
