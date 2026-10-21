// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

//! Local-only file host used when the default HTTP transport is disabled.

use std::{fs::File, path::Path};

use contentauth_c2pa_file_reader::{read_manifest, ReadReport, ReadSettings};

use crate::{format, Error};

pub(crate) fn read_and_validate(path: &Path, settings: ReadSettings) -> Result<ReadReport, Error> {
    let mut source = File::open(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let handler = format::choose(path, &mut source)?;
    Ok(read_manifest(&handler, source, settings)?)
}
