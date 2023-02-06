use uuid::Uuid;
use std::rc::Rc;
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use webauthn_rs_device_catalog::quirks::Quirk;

use base64urlsafedata::Base64UrlSafeData;

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Manufacturer {

    // Our name of the mfr, must be unique.
    name: String,

    // Strings that match them to a Fido String
    fido_names: Vec<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Sku {

    // Level

    // Number of Rk

    // Signing CA
    pub attestation_cas: Vec<Base64UrlSafeData>,
}

#[derive(Default, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FidoMdsLink {
    /// This metadata is extending an existing device.
    #[default]
    Extend,
    /// This metadata is a unique device, but exists as a clone of another
    /// device in the MDS. The classic example is the Token T2F2 being a clone and repackage
    /// of the "Feitian ePass FIDO2 Authenticator"
    Clone,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Device {
    // The aaguid this device implements
    pub aaguid: Uuid,

    #[serde(default)]
    pub mds_link: FidoMdsLink,

    // Denote if a known aaguid conflict exists.
    // aaguid_conflict: bool,

    // Display Name
    pub display_name: String,

    // A list of manufacturers
    // manufacturer: Rc<Manufacturer>

    #[serde(default)]
    pub quirks: BTreeSet<Quirk>,

    // Lowest common denominator of levels / values

    #[serde(default)]
    pub skus: Vec<Sku>,

    #[serde(default)]
    pub images: Vec<String>,
}

