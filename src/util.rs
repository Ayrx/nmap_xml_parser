use crate::Error;
use roxmltree::Node;
use std::str::FromStr;

pub fn parse_node_attr<T: FromStr>(node: Node, attribute: &str) -> Result<T, Error> {
    node.attribute(attribute)
        .ok_or_else(|| {
            Error::from(
                format!(
                    "expected `{}` attribute in `{}`",
                    attribute,
                    node.tag_name().name()
                )
                .as_str(),
            )
        })
        .and_then(|s| {
            s.parse::<T>()
                .map_err(|_| Error::from(format!("failed to parse `{}`", attribute).as_str()))
        })
}

pub fn node_attr_as_string(node: Node, attribute: &str) -> Result<String, Error> {
    Ok(node
        .attribute(attribute)
        .ok_or_else(|| {
            Error::from(
                format!(
                    "expected `{}` attribute in `{}` node",
                    attribute,
                    node.tag_name().name()
                )
                .as_str(),
            )
        })?
        .to_string())
}
