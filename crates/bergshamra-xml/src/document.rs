#![forbid(unsafe_code)]

//! XML document wrapper over uppsala with ID attribute registration.

use bergshamra_core::Error;
use std::collections::HashMap;
use uppsala::{Document, NodeId};

/// An owned XML document.  Stores the text and pre-computed metadata.
///
/// To work with the parsed tree, call [`XmlDocument::parse_doc`] which
/// returns a temporary `Document` borrowing from the text.
pub struct XmlDocument {
    text: String,
    /// Additional ID attribute names to register (beyond the default `Id`, `ID`, `id`).
    extra_id_attrs: Vec<String>,
}

impl XmlDocument {
    /// Parse and validate XML from a string, taking ownership.
    pub fn parse(text: String) -> Result<Self, Error> {
        // Validate that the XML parses successfully.
        let _doc = uppsala::parse(&text).map_err(|e| Error::XmlParse(e.to_string()))?;
        Ok(Self {
            text,
            extra_id_attrs: Vec::new(),
        })
    }

    /// Parse and validate XML from bytes.
    pub fn parse_bytes(data: &[u8]) -> Result<Self, Error> {
        let text = std::str::from_utf8(data)
            .map_err(|e| Error::XmlParse(format!("invalid UTF-8: {e}")))?
            .to_owned();
        Self::parse(text)
    }

    /// Get the raw XML text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Register additional ID attribute names (e.g., `"wsu:Id"`).
    pub fn add_id_attr(&mut self, name: &str) {
        self.extra_id_attrs.push(name.to_owned());
    }

    /// Parse the document and return a temporary `Document`.
    ///
    /// This re-parses the XML from the stored text.  For performance,
    /// call this once at the top of a processing pipeline and pass the
    /// resulting document reference down through the call chain.
    pub fn parse_doc(&self) -> Result<Document<'_>, Error> {
        uppsala::parse(&self.text).map_err(|e| Error::XmlParse(e.to_string()))
    }

    /// Build the ID → NodeId mapping for a parsed document.
    ///
    /// Returns an error if the same ID value appears on more than one element
    /// across any registered ID attribute (`Id`, `ID`, `id`, `AssertionID`,
    /// `xml:id`, and any names added via [`XmlDocument::add_id_attr`]).
    /// Silently accepting duplicates enables XML Signature Wrapping (XSW),
    /// where an injected element shadows the one that was actually signed.
    pub fn build_id_map(&self, doc: &Document<'_>) -> Result<HashMap<String, NodeId>, Error> {
        // Matched by local name, so `wsu:Id` is also treated as `Id`.
        let default_attrs = ["Id", "ID", "id", "AssertionID"];
        let mut map = HashMap::new();
        for id in doc.descendants(doc.root()) {
            let Some(elem) = doc.element(id) else { continue };
            for attr_name in &default_attrs {
                if let Some(val) = elem.get_attribute(attr_name) {
                    insert_unique_id(&mut map, val, id)?;
                }
            }
            // `xml:id` is namespace-qualified (local name "id" in the XML
            // namespace); a plain local-name lookup of "xml:id" never matches.
            if let Some(val) = elem.get_attribute_ns(bergshamra_core::ns::XML, "id") {
                insert_unique_id(&mut map, val, id)?;
            }
            for attr_name in &self.extra_id_attrs {
                if let Some(val) = elem.get_attribute(attr_name.as_str()) {
                    insert_unique_id(&mut map, val, id)?;
                }
            }
        }
        Ok(map)
    }

    /// Find an element by its registered ID value in a parsed document.
    pub fn find_by_id(
        _doc: &Document<'_>,
        id_map: &HashMap<String, NodeId>,
        id: &str,
    ) -> Option<NodeId> {
        id_map.get(id).copied()
    }

    /// Find the first descendant element with the given local name and namespace.
    pub fn find_element(doc: &Document<'_>, ns: &str, local_name: &str) -> Option<NodeId> {
        let results = doc.get_elements_by_tag_name_ns(ns, local_name);
        results.into_iter().next()
    }

    /// Find all descendant elements with the given local name and namespace.
    pub fn find_elements(doc: &Document<'_>, ns: &str, local_name: &str) -> Vec<NodeId> {
        doc.get_elements_by_tag_name_ns(ns, local_name)
    }
}

/// Insert an ID → node mapping, rejecting a value already bound to a
/// *different* element (the XML Signature Wrapping primitive). Re-binding the
/// same node via a second ID attribute (e.g. an overlapping `extra_id_attr`)
/// is allowed.
fn insert_unique_id(
    map: &mut HashMap<String, NodeId>,
    val: &str,
    id: NodeId,
) -> Result<(), Error> {
    match map.insert(val.to_owned(), id) {
        Some(prev) if prev != id => Err(Error::XmlStructure(format!("duplicate ID: {val}"))),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(xml: &str) -> Result<HashMap<String, NodeId>, Error> {
        let xdoc = XmlDocument::parse(xml.to_owned()).unwrap();
        let doc = xdoc.parse_doc().unwrap();
        xdoc.build_id_map(&doc)
    }

    #[test]
    fn unique_ids_map_correctly() {
        let map = build(r#"<root><a Id="a1"/><b ID="b2"/><c id="c3"/></root>"#).unwrap();
        assert_eq!(map.len(), 3);
        assert!(map.contains_key("a1") && map.contains_key("b2") && map.contains_key("c3"));
    }

    #[test]
    fn rejects_duplicate_ids() {
        // Two distinct elements sharing Id="dup" is the XSW primitive.
        let err = build(r#"<root><a Id="dup">x</a><b Id="dup">y</b></root>"#).unwrap_err();
        assert!(matches!(err, Error::XmlStructure(_)));
        assert!(err.to_string().contains("duplicate ID"));
    }

    #[test]
    fn rejects_duplicate_across_attr_casings() {
        let err = build(r#"<root><a Id="x"/><b id="x"/></root>"#).unwrap_err();
        assert!(err.to_string().contains("duplicate ID"));
    }

    #[test]
    fn maps_saml_assertion_id() {
        let map = build(r#"<Assertion AssertionID="A1"/>"#).unwrap();
        assert!(map.contains_key("A1"), "AssertionID must be a default ID attr");
    }

    #[test]
    fn maps_xml_id_namespaced() {
        let map = build(r#"<root xml:id="r1"/>"#).unwrap();
        assert!(map.contains_key("r1"), "xml:id must resolve via the XML namespace");
    }

    #[test]
    fn overlapping_extra_id_attr_is_not_a_duplicate() {
        // Re-registering "Id" must not flag a single element as a duplicate.
        let mut xdoc = XmlDocument::parse(r#"<a Id="x"/>"#.to_owned()).unwrap();
        xdoc.add_id_attr("Id");
        let doc = xdoc.parse_doc().unwrap();
        assert!(xdoc.build_id_map(&doc).is_ok());
    }

    #[test]
    fn find_by_id_resolves_node() {
        let xdoc = XmlDocument::parse(r#"<root><a Id="a1"/></root>"#.to_owned()).unwrap();
        let doc = xdoc.parse_doc().unwrap();
        let map = xdoc.build_id_map(&doc).unwrap();
        let node = XmlDocument::find_by_id(&doc, &map, "a1").unwrap();
        assert_eq!(doc.element(node).unwrap().name.local_name.as_ref(), "a");
    }
}
