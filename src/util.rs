use const_format::formatcp;

macro_rules! parse_node_attr {
    ($node:expr, $nodename:expr, $attribute:expr, $type:ty) => {{
        $node
            .attribute($attribute)
            .ok_or_else(|| {
                Error::from(formatcp!(
                    "expected `{}` attribute in `{}`",
                    $attribute,
                    $nodename
                ))
            })
            .and_then(|s| {
                s.parse::<$type>()
                    .map_err(|_| Error::from(formatcp!("failed to parse `{}`", $attribute)))
            })
    }};
}

macro_rules! node_attr_as_string {
    ($node:expr, $nodename:expr, $attribute:expr) => {{
        Ok($node
            .attribute($attribute)
            .ok_or_else(|| {
                Error::from(formatcp!(
                    "expected `{}` attribute in `{}` node",
                    $attribute,
                    $nodename
                ))
            })?
            .to_string())
    }};
}

pub(crate) use node_attr_as_string;
pub(crate) use parse_node_attr;
