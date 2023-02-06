use uuid::Uuid;
use std::path::{PathBuf, Path};
use webauthn_rs_device_catalog::quirks::{Quirk, Quirks};
use webauthn_rs_device_catalog::device_statements::{Mds, Authority as MdsAuthority, Sku as MdsSku};
use std::fs;
use std::collections::{HashMap, BTreeMap};
use std::collections::BTreeSet;
use fido_mds::FidoMds;
use base64urlsafedata::Base64UrlSafeData;

use crate::proto::{Device, Manufacturer, FidoMdsLink};

use tracing::{debug, info, trace, warn, error};

pub struct Enrichment {
    devices: Vec<Device>,
    manufacturers: Vec<Manufacturer>,
}

impl Enrichment {
    pub fn new(root: &Path) -> Result<Self, ()> {
        if !root.is_dir() {
            error!("not a directory");
            return Err(());
        }

        let hw_path = root.join("hw");
        if !hw_path.exists() || !hw_path.is_dir() {
            error!("hw folder is invalid");
            return Err(());
        }

        let mfr_path = root.join("mfr");
        if !mfr_path.exists() || !mfr_path.is_dir() {
            error!("mfr folder is invalid");
            return Err(());
        }

        // We have to parse each folder in the aaguid_path, both their path to a UUID
        // and the content of the folder into the various types we have.

        let mut devices = Vec::new();

        // Do we have the hw folder?
        for hw_ent in hw_path.read_dir()
            .map_err(|e| {
                error!("unable to read_dir over hw_path");
            })? {

            let hw_ent = hw_ent.map_err(|e| {
                error!("unable to process dir ent in hw_path {:?}", e);
            })?;

            // I think we ignore the path name, and just process what's in it.
            // Open the ent/device.json
            let hw_ent_device_path = hw_ent.path().join("device.json");
            if hw_ent_device_path.exists() {
                let mut hw_ent_device_file = fs::File::open(&hw_ent_device_path)
                    .map_err(|e| {
                        error!("failed to open hw_ent {:?} {:?}", hw_ent_device_path, e);
                    })?;

                let device: Device = serde_json::from_reader(hw_ent_device_file)
                    .map_err(|e| {
                        error!("invalid content hw_ent {:?} {:?}", hw_ent_device_path, e);
                    })?;

                devices.push(device);
            }
        }

        // Do we have the images db?

        // Find all the aaguids we have.

        // Find all the hw versions we have.

        let mut manufacturers = Vec::new();
        for mfr_ent in mfr_path.read_dir()
            .map_err(|e| {
                error!("unable to read_dir over hw_path");
            })? {

            let mfr_ent = mfr_ent.map_err(|e| {
                error!("unable to process dir ent in mfr_path {:?}", e);
            })?;

            let mut mfr_ent_file = fs::File::open(&mfr_ent.path())
                .map_err(|e| {
                    error!("failed to open mfr_ent_ent {:?} {:?}", mfr_ent.path(), e);
                })?;

            let mfr: Manufacturer = serde_json::from_reader(mfr_ent_file)
                .map_err(|e| {
                    error!("invalid content hw_ent {:?} {:?}", mfr_ent.path(), e);
                })?;

            manufacturers.push(mfr);
        }


        Ok(Enrichment {
            devices,
            manufacturers
        })

    }
}

impl Into<Quirks> for &Enrichment {
    fn into(self) -> Quirks {
        let mut quirks = Quirks::default();

        for device in self.devices.iter() {
            if device.quirks.is_empty() {
                // Don't add devices that have no quirks.
                continue;
            }

            if !quirks.contains_key(&device.aaguid) {
                quirks.insert(device.aaguid, BTreeSet::new());
            }

            let aaguid_quirks = quirks.get_mut(&device.aaguid)
                .expect("Corrupt device quirks set");
            aaguid_quirks.extend(device.quirks.iter());
        }

        quirks
    }
}


#[derive(Debug, Clone)]
struct EnrichedDevice {
    // An indicator of data source

    pub aaguid: Uuid,

    pub display_name: String,

    pub quirks: BTreeSet<Quirk>,

    // Worried we may need multiple?
    pub ca: Vec<Base64UrlSafeData>,

    // Need to have multiple CA's here?
    // pub ca: Vec<>,
}

pub struct EnrichedMds {
    // We need to build some other indexes here?
    devices: Vec<EnrichedDevice>,
    // manufacturers: BTreeMap<String, Manufacturer>,
}

impl TryFrom<(&FidoMds, &Enrichment)> for EnrichedMds {
    type Error = ();

    fn try_from((fido_mds, enrichment): (&FidoMds, &Enrichment)) -> Result<Self, Self::Error> {

        // Get the set of all aaguids between both.
        //    Then push in stuff. Aaguids aren't a 1 to 1 map at this point. We're using them as a way
        //    to link things together. We do it this way because aaguids are one of the only signals
        //    we have for device id aside from the ca in use. However we will invert and break this down
        //    to ca linked maps in this process.

        // We need to setup enrichment data by aaguid key.
        let mut enrich_map: BTreeMap<_, Vec<_>> = BTreeMap::default();

        for edev in enrichment.devices.iter() {
            let dev_list = enrich_map.entry(edev.aaguid)
                .or_default();

            dev_list.push(edev);
        }

        let mut fido_map: BTreeMap<_, Vec<_>> = BTreeMap::default();

        for fdev in fido_mds.fido2.iter() {
            let dev_list = fido_map.entry(fdev.aaguid)
                .or_default();

            dev_list.push(fdev);
        }

        // The full set of aaguids between fido *and* us.
        let aaguid_set: BTreeSet<_> = fido_map.keys()
            .chain(enrich_map.keys())
            .copied()
            // HACK HACK HACK - just limit to some test keys / situations!
            .filter(|aaguid| {
                *aaguid == uuid::uuid!("c39efba6-fcf4-4c3e-828b-fc4a6115a0ff") ||
                *aaguid == uuid::uuid!("ab32f0c6-2239-afbb-c470-d2ef4e254db7") ||
                *aaguid == uuid::uuid!("833b721a-ff5f-4d00-bb2e-bdda3ec01e29") ||
                *aaguid == uuid::uuid!("54d9fee8-e621-4291-8b18-7157b99c5bec")
            })
            .collect();

        // Now build the full map.
        //  If we don't have anything -> process mds to our format
        //  If we have something + fido -> proccess mds to our format -> apply our enrichment
        //  If we have something + no fido -> enrich to our data.

        let mut devices = Vec::new();

        for aaguid in aaguid_set {
            let maybe_fdevs = fido_map.get(&aaguid);
            let maybe_edevs = enrich_map.get(&aaguid);
            trace!("Working on {} - fido {} enrich {}", aaguid, maybe_fdevs.is_some(), maybe_edevs.is_some() );

            match (maybe_fdevs, maybe_edevs) {
                (Some(fdevs), Some(edevs)) => {
                    if fdevs.len() != 1 {
                        error!("FIDO claim aaguids are unique, but {} has a duplication", aaguid);
                        return Err(());
                    }

                    let fdev = fdevs[0];

                    for edev in edevs {
                        match edev.mds_link {
                            FidoMdsLink::Extend => {
                                // We are extending fdev with this data.
                                devices.push(EnrichedDevice {
                                    aaguid: fdev.aaguid,
                                    display_name: fdev.description.clone(),
                                    quirks: edev.quirks.clone(),
                                    ca: fdev.attestation_root_certificates
                                        .iter().cloned().map(|d| d.into())
                                        .collect(),
                                })
                            }
                            FidoMdsLink::Clone => {
                                // A clone device exists, so we don't take everything
                                // in the same way. Mainly because we actually need to
                                // override a number of the id/display fields.
                                devices.push(EnrichedDevice {
                                    aaguid: edev.aaguid,
                                    display_name: edev.display_name.clone(),
                                    quirks: edev.quirks.clone(),
                                    ca: fdev.attestation_root_certificates
                                        .iter().cloned().map(|d| d.into())
                                        .collect(),
                                })
                            }
                        }
                    }

                }
                (Some(fdevs), None) => {
                    // Create an entry from a fido device.
                    if fdevs.len() != 1 {
                        error!("FIDO claim aaguids are unique, but {} has a duplication", aaguid);
                        return Err(());
                    }

                    let fdev = fdevs[0];

                    // for fdev in fdevs {
                        devices.push(EnrichedDevice {
                            aaguid: fdev.aaguid,
                            display_name: fdev.description.clone(),
                            quirks: Default::default(),
                            ca: fdev.attestation_root_certificates
                                .iter().cloned().map(|d| d.into())
                                .collect(),
                        })
                    // }
                }
                (None, Some(edevs)) => {
                    for edev in edevs {
                        devices.push(EnrichedDevice {
                            aaguid: edev.aaguid,
                            display_name: edev.display_name.clone(),
                            quirks: edev.quirks.clone(),
                            ca: edev.skus.iter().flat_map(|sku| sku.attestation_cas.iter())
                                .cloned()
                                .collect(),
                        })
                    }
                }
                (None, None) => {
                    warn!("Invalid uuid? Not sure how this happened ...");
                }
            }
        }

        Ok(EnrichedMds {
            devices,
        })
    }
}

impl Into<Mds> for &EnrichedMds {
    fn into(self) -> Mds {
        let mut mds = Mds::default();

        let mut work_map: HashMap<_, Vec<_>> = HashMap::new();

        // for each device
        //   get the set of ca's -> skus

        for dev in self.devices.iter() {
            trace!(?dev);

            let sku = MdsSku {
                aaguid: dev.aaguid,
                display_name: dev.display_name.clone(),
            };

            // We key from the owning CA.
            for ca in &dev.ca {
                let dev_list = work_map.entry(ca.clone())
                    .or_default();

                dev_list.push(sku.clone());
            }
        }

        work_map.into_iter().map(|(ca, skus)| {
            MdsAuthority {
                ca: ca.clone(),
                skus
            }
        })
        .collect()
    }
}

