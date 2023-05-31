

use crate::UserVerificationMethod;
use uuid::Uuid;
use tracing::{trace, warn};

use std::hash::{Hash, Hasher};

#[allow(deprecated)]
use std::hash::SipHasher;

const YK5LIGHTNING: Uuid = uuid::uuid!("c5ef55ff-ad9a-4b9f-b580-adebafe026d0");
const YK5LIGHTNING_HASH: u64 = 9891217653727489461;

pub(crate) fn user_verification_method(
    aaguid: Option<Uuid>,
    uvm: &Vec<Vec<UserVerificationMethod>>,
) -> Result<Option<Vec<Vec<UserVerificationMethod>>>, ()> {
    #[allow(deprecated)]
    let mut hasher = SipHasher::new();
    uvm.hash(&mut hasher);
    let hash = hasher.finish();

    match aaguid {
        Some(aaguid) => {
            trace!(?aaguid, ?uvm, ?hash);
            if aaguid == YK5LIGHTNING {
                if hash == YK5LIGHTNING_HASH {
                    user_verification_method_yk5lightning(uvm)
                        .map(Some)
                } else {
                    warn!("Hash for {} hash changed ({}), this must be inspected manually", hash, YK5LIGHTNING);
                    Err(())
                }

            } else {
                Ok(None)
            }
        }
        None => Ok(None)
    }
}

fn user_verification_method_yk5lightning(uvm_and: &Vec<Vec<UserVerificationMethod>>)
    -> Result<Vec<Vec<UserVerificationMethod>>, ()> {

    trace!(?uvm_and);

    todo!()

}

