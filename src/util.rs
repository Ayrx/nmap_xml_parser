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
            })?
    }};
}

macro_rules! node_attr_as_string {
    ($node:expr, $nodename:expr, $attribute:expr) => {{
        $node
            .attribute($attribute)
            .ok_or_else(|| {
                Error::from(formatcp!(
                    "expected `{}` attribute in `{}` node",
                    $attribute,
                    $nodename
                ))
            })?
            .to_string()
    }};
}

macro_rules! from_node_attr {
    ($node:expr, $nodename:expr, $attribute:expr, $type:ty) => {{
        let s = $node.attribute($attribute).ok_or_else(|| {
            Error::from(formatcp!(
                "expected `{}` attribute in `{}` node",
                $attribute,
                $nodename
            ))
        })?;
        <$type>::from_str(s)
            .map_err(|_| Error::from(formatcp!("failed to parse {}", stringify!($type))))?
    }};
}

pub(crate) use from_node_attr;
pub(crate) use node_attr_as_string;
pub(crate) use parse_node_attr;
