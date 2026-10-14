//! Namespace-aware remote references in standard JPEG XMP packets.

use contentauth_c2pa_format::FormatError;

const STANDARD: &[u8] = b"http://ns.adobe.com/xap/1.0/\0";
const EXTENDED: &[u8] = b"http://ns.adobe.com/xmp/extension/\0";
const DCTERMS: &str = "http://purl.org/dc/terms/";
const RDF: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#";

pub(crate) fn provenance(contents: &[u8]) -> Result<Option<String>, FormatError> {
    if contents.starts_with(EXTENDED) {
        return Err(FormatError::Unsupported(
            "JPEG extended XMP is not supported".into(),
        ));
    }
    let Some(xml) = contents.strip_prefix(STANDARD) else {
        return Ok(None);
    };
    let xml = core::str::from_utf8(xml)
        .map_err(|err| FormatError::Malformed(format!("JPEG XMP is not UTF-8: {err}")))?;
    let document = roxmltree::Document::parse_with_options(
        xml.trim_end_matches('\0'),
        roxmltree::ParsingOptions {
            allow_dtd: false,
            nodes_limit: 4096,
            ..Default::default()
        },
    )
    .map_err(|err| FormatError::Malformed(format!("JPEG XMP: {err}")))?;
    let mut result = None;
    for node in document.descendants().filter(roxmltree::Node::is_element) {
        for attribute in node.attributes() {
            if attribute.namespace() == Some(DCTERMS) && attribute.name() == "provenance" {
                set(&mut result, attribute.value())?;
            }
        }
        if node.tag_name().namespace() == Some(DCTERMS) && node.tag_name().name() == "provenance" {
            if node.children().any(|child| child.is_element()) {
                return Err(FormatError::Unsupported(
                    "JPEG XMP provenance must be a simple value".into(),
                ));
            }
            let text: String = node
                .children()
                .filter(|child| child.is_text())
                .filter_map(|child| child.text())
                .collect();
            let value = match node.attribute((RDF, "resource")) {
                Some(resource) if text.trim().is_empty() => resource,
                Some(_) => {
                    return Err(FormatError::Malformed(
                        "JPEG XMP provenance has both text and a resource".into(),
                    ));
                }
                None => &text,
            };
            set(&mut result, value)?;
        }
    }
    Ok(result)
}

fn set(result: &mut Option<String>, value: &str) -> Result<(), FormatError> {
    let value = value.trim();
    if value.is_empty() || result.is_some() {
        return Err(FormatError::Malformed(
            "JPEG XMP has empty or multiple provenance references".into(),
        ));
    }
    *result = Some(value.into());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(xml: &str) -> Vec<u8> {
        [STANDARD, xml.as_bytes()].concat()
    }

    #[test]
    fn namespace_and_entities_not_prefix_spelling_determine_the_reference() {
        let xml = r#"<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:p="http://purl.org/dc/terms/"><rdf:Description p:provenance="https://example.test/store?a=1&amp;b=2"/></rdf:RDF>"#;
        assert_eq!(
            provenance(&packet(xml)).ok().flatten().as_deref(),
            Some("https://example.test/store?a=1&b=2")
        );
        assert_eq!(
            provenance(&packet(&xml.replace(DCTERMS, "https://wrong.test/"))).ok(),
            Some(None)
        );
    }

    #[test]
    fn text_and_rdf_resource_forms_are_supported() {
        for value in [
            "https://example.test/store",
            r#"<p:provenance rdf:resource="https://example.test/store"/>"#,
        ] {
            let element = if value.starts_with('<') {
                value.to_string()
            } else {
                format!("<p:provenance>{value}</p:provenance>")
            };
            let xml = format!(
                r#"<rdf:RDF xmlns:rdf="{RDF}" xmlns:p="{DCTERMS}"><rdf:Description>{element}</rdf:Description></rdf:RDF>"#
            );
            assert_eq!(
                provenance(&packet(&xml)).ok().flatten().as_deref(),
                Some("https://example.test/store")
            );
        }
    }

    #[test]
    fn malformed_ambiguous_and_dtd_packets_fail_explicitly() {
        for xml in [
            "<unclosed>",
            "<!DOCTYPE x [<!ENTITY url 'https://example.test'>]><x/>",
            r#"<x xmlns:p="http://purl.org/dc/terms/" p:provenance=""/>"#,
            r#"<x xmlns:p="http://purl.org/dc/terms/" p:provenance="one"><p:provenance>two</p:provenance></x>"#,
        ] {
            assert!(provenance(&packet(xml)).is_err());
        }
        assert!(provenance(EXTENDED).is_err());
        assert!(provenance(&packet(&format!("<x>{}</x>", "<n/>".repeat(4096)))).is_err());
        assert_eq!(provenance(b"Exif\0\0data").ok(), Some(None));
    }
}
