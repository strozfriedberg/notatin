use serde::Serialize;
use crate::hive_bin_header;

/* Structures based upon:
    https://github.com/libyal/libregf/blob/main/documentation/Windows%20NT%20Registry%20File%20(REGF)%20format.asciidoc
    https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md#format-of-primary-files

    Summary
        A Base block points to a root cell, which contains a Key node.
        A Key node points to a parent Key node, to a Subkeys list (a subkey is a Key node too), to a Key values list, to a Key security item.
        A Subkeys list can be subdivided with the help of the Index root structure.
        A Key value points to data. Data may be stored in the Data offset field of a Key value structure, in a separate cell, or in a bunch of cells. In the last case, a Key value points to the Big data structure in a cell.
*/

/* Cell data may contain one of the following records:
    Record	Description
    Index leaf (li)	Subkeys list
    Fast leaf (lf)	Subkeys list with name hints
    Hash leaf (lh)	Subkeys list with name hashes
    Index root (ri)	List of subkeys lists (used to subdivide subkeys lists)
    Key node (nk)	Registry key node
    Key value (vk)	Registry key value
    Key security (sk)	Security descriptor
    Big data (db)	List of data segments
*/

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct HiveBin {
    pub hive_bin: hive_bin_header::HiveBinHeader,
}