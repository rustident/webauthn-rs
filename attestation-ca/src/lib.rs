use base64urlsafedata::Base64UrlSafeData;
use openssl::error::ErrorStack as OpenSSLErrorStack;
use openssl::{hash, x509};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use uuid::Uuid;

/// A serialised Attestation CA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerialisableAttestationCa {
    pub(crate) ca: Base64UrlSafeData,
    pub(crate) aaguids: BTreeSet<Uuid>,
}

/// A structure representing an Attestation CA and other options associated to this CA.
///
/// Generally depending on the Attestation CA in use, this can help determine properties
/// of the authenticator that is in use.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    try_from = "SerialisableAttestationCa",
    into = "SerialisableAttestationCa"
)]
pub struct AttestationCa {
    /// The x509 root CA of the attestation chain that a security key will be attested to.
    pub ca: x509::X509,
    /// If not empty, the set of acceptable AAGUIDS (Device Ids) that are allowed to be
    /// attested as trusted by this CA. AAGUIDS that are not in this set, but signed by
    /// this CA will NOT be trusted.
    pub aaguids: BTreeSet<Uuid>,
}

#[allow(clippy::from_over_into)]
impl Into<SerialisableAttestationCa> for AttestationCa {
    fn into(self) -> SerialisableAttestationCa {
        SerialisableAttestationCa {
            ca: Base64UrlSafeData(self.ca.to_der().expect("Invalid DER")),
            aaguids: self.aaguids,
        }
    }
}

impl TryFrom<SerialisableAttestationCa> for AttestationCa {
    type Error = OpenSSLErrorStack;

    fn try_from(data: SerialisableAttestationCa) -> Result<Self, Self::Error> {
        Ok(AttestationCa {
            ca: x509::X509::from_der(&data.ca.0)?,
            aaguids: data.aaguids,
        })
    }
}

impl TryFrom<&[u8]> for AttestationCa {
    type Error = OpenSSLErrorStack;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        Ok(AttestationCa {
            ca: x509::X509::from_pem(data)?,
            aaguids: Default::default(),
        })
    }
}

impl AttestationCa {
    /// Retrieve the Key Identifier for this Attestation Ca
    pub fn get_kid(&self) -> Result<Vec<u8>, OpenSSLErrorStack> {
        self.ca
            .digest(hash::MessageDigest::sha256())
            .map(|bytes| bytes.to_vec())
    }

    /// Update the set of aaguids this Attestation CA allows. If an empty btreeset is provided then
    /// this Attestation CA allows all Aaguids.
    pub fn set_aaguids(&mut self, aaguids: BTreeSet<Uuid>) {
        self.aaguids = aaguids;
    }

    /// Update the set of aaguids this Attestation CA allows by adding this AAGUID to the allowed
    /// set.
    pub fn insert_aaguid(&mut self, aaguid: Uuid) {
        self.aaguids.insert(aaguid);
    }

    /// Create a customised attestation CA from a DER public key.
    pub fn new_from_der(data: &[u8]) -> Result<Self, OpenSSLErrorStack> {
        Ok(AttestationCa {
            ca: x509::X509::from_der(data)?,
            aaguids: BTreeSet::default(),
        })
    }

    /*
    /// The Apple TouchID and FaceID root CA.
    pub fn apple_webauthn_root_ca() -> Self {
        AttestationCa {
            ca: x509::X509::from_pem(APPLE_WEBAUTHN_ROOT_CA_PEM).expect("Invalid DER"),
            aaguids: BTreeSet::default(),
        }
    }

    /// The yubico u2f root ca. Applies to all devices up to and including series 5.
    pub fn yubico_u2f_root_ca_serial_457200631() -> Self {
        AttestationCa {
            ca: x509::X509::from_pem(YUBICO_U2F_ROOT_CA_SERIAL_457200631_PEM).expect("Invalid DER"),
            aaguids: BTreeSet::default(),
        }
    }

    /// The microsoft root CA for TPM attestation.
    ///
    /// Not eligible for strict - many TPM's use SHA1 in signatures, which means they are
    /// potentially weak.
    ///
    /// In the future we may reject RS1 signatures, allowing this to be moved into the
    /// strict category.
    pub fn microsoft_tpm_root_certificate_authority_2014() -> Self {
        AttestationCa {
            ca: x509::X509::from_pem(MICROSOFT_TPM_ROOT_CERTIFICATE_AUTHORITY_2014_PEM)
                .expect("Invalid DER"),
            aaguids: BTreeSet::default(),
        }
    }

    /// Nitrokey root CA for their FIDO2 device range.
    ///
    /// Not eligible for strict - hardware is difficult to interact with, low quality,
    /// and easy to break or destroy.
    pub fn nitrokey_fido2_root_ca() -> Self {
        AttestationCa {
            ca: x509::X509::from_pem(NITROKEY_FIDO2_ROOT_CA_PEM).expect("Invalid DER"),
            aaguids: BTreeSet::default(),
        }
    }

    /// Nitrokey root CA for their U2F device range.
    ///
    /// Not eligible for strict - hardware is difficult to interact with, low quality,
    /// and easy to break or destroy.
    pub fn nitrokey_u2f_root_ca() -> Self {
        AttestationCa {
            ca: x509::X509::from_pem(NITROKEY_U2F_ROOT_CA_PEM).expect("Invalid DER"),
            aaguids: BTreeSet::default(),
        }
    }

    /// Android ROOT CA 1
    pub fn android_root_ca_1() -> Self {
        AttestationCa {
            ca: x509::X509::from_pem(ANDROID_ROOT_CA_1).expect("Invalid DER"),
            aaguids: BTreeSet::default(),
        }
    }

    /// Android ROOT CA 2
    pub fn android_root_ca_2() -> Self {
        AttestationCa {
            ca: x509::X509::from_pem(ANDROID_ROOT_CA_2).expect("Invalid DER"),
            aaguids: BTreeSet::default(),
        }
    }

    /// Android ROOT CA 3
    pub fn android_root_ca_3() -> Self {
        AttestationCa {
            ca: x509::X509::from_pem(ANDROID_ROOT_CA_3).expect("Invalid DER"),
            aaguids: BTreeSet::default(),
        }
    }

    /// Android SOFTWARE ONLY root CA
    pub fn android_software_ca() -> Self {
        AttestationCa {
            ca: x509::X509::from_pem(ANDROID_SOFTWARE_ROOT_CA).expect("Invalid DER"),
            aaguids: BTreeSet::default(),
        }
    }

    /// Google SafetyNet CA (for android)
    pub fn google_safetynet_ca() -> Self {
        AttestationCa {
            ca: x509::X509::from_pem(GOOGLE_SAFETYNET_CA).expect("Invalid DER"),
            aaguids: BTreeSet::default(),
        }
    }

    /// Google SafetyNet CA (for android) -- OLD EXPIRED
    #[allow(unused)]
    pub(crate) fn google_safetynet_ca_old() -> Self {
        AttestationCa {
            ca: x509::X509::from_pem(GOOGLE_SAFETYNET_CA_OLD).expect("Invalid DER"),
            aaguids: BTreeSet::default(),
        }
    }
    */
}

/// A list of AttestationCas and associated options.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AttestationCaList {
    /// The set of CA's that we trust in this Operation
    pub cas: BTreeMap<Base64UrlSafeData, AttestationCa>,
}

impl TryFrom<AttestationCa> for AttestationCaList {
    type Error = OpenSSLErrorStack;

    fn try_from(att_ca: AttestationCa) -> Result<Self, Self::Error> {
        let mut new = Self::default();
        new.insert(att_ca)?;
        Ok(new)
    }
}

impl TryFrom<&[u8]> for AttestationCaList {
    type Error = OpenSSLErrorStack;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let mut new = Self::default();
        let att_ca = AttestationCa::try_from(data)?;
        new.insert(att_ca)?;
        Ok(new)
    }
}

impl FromIterator<(x509::X509, Uuid)> for AttestationCaList {
    fn from_iter<I: IntoIterator<Item = (x509::X509, Uuid)>>(iter: I) -> Self {
        let mut cas = BTreeMap::default();

        for (ca, aaguid) in iter {
            let kid = ca
                .digest(hash::MessageDigest::sha256())
                // Is there a better way to do this with fromIterator?
                .unwrap();

            if !cas.contains_key(kid.as_ref()) {
                let mut aaguids = BTreeSet::default();
                aaguids.insert(aaguid);
                let att_ca = AttestationCa { ca, aaguids };
                cas.insert(kid.to_vec().into(), att_ca);
            } else {
                let att_ca = cas.get_mut(kid.as_ref()).expect("Can not fail!");
                // just add the aaguid
                att_ca.aaguids.insert(aaguid);
            };
        }

        AttestationCaList { cas }
    }
}

impl AttestationCaList {
    /// Determine if this attestation list contains any members.
    pub fn is_empty(&self) -> bool {
        self.cas.is_empty()
    }

    /// Insert a new att_ca into this Attestation Ca List
    pub fn insert(
        &mut self,
        att_ca: AttestationCa,
    ) -> Result<Option<AttestationCa>, OpenSSLErrorStack> {
        // Get the key id (kid, digest).
        let att_ca_dgst = att_ca.get_kid()?;
        Ok(self.cas.insert(att_ca_dgst.into(), att_ca))
    }
}
