//! Rust values ⇄ plain JS values.
//!
//! Records cross as plain JS objects with camelCase keys (the TS SDK's style), unit enums as their
//! wire strings, bytes as `Uint8Array`, `Option` as `undefined` (and `null` on input), integers as
//! `number`. The [`record!`] and [`unit_enum!`] macros write both directions and the matching
//! TypeScript declaration (a `typescript_custom_section`), so the `.d.ts` can't drift from the code.

use js_sys::{Array, Object, Reflect, Uint8Array};
use ov_error::{OvError, OvErrorCode};
use wasm_bindgen::{JsCast, JsValue};

/// A Rust value that becomes a JS value.
pub(crate) trait ToJs {
    fn to_js(&self) -> JsValue;
}

/// A Rust value read from a JS value. `path` names the value in error messages (`input.email`).
pub(crate) trait FromJs: Sized {
    fn from_js(v: &JsValue, path: &str) -> Result<Self, OvError>;
}

/// Element types of `Vec<T>` ⇄ `Array`. `u8` is not one: `Vec<u8>` is a `Uint8Array`.
pub(crate) trait Elem: ToJs + FromJs {}

/// `invalid_request: <path>: expected <want>`.
pub(crate) fn bad(path: &str, want: &str) -> OvError {
    OvError::new(OvErrorCode::InvalidRequest, format!("{path}: expected {want}"))
}

/// A fresh empty object.
pub(crate) fn obj() -> Object {
    Object::new()
}

/// `o[key] = value`, skipping `undefined` so optional fields are absent rather than present-undefined.
pub(crate) fn set(o: &Object, key: &str, value: JsValue) {
    if !value.is_undefined() {
        // Setting a property on a plain fresh object can't fail.
        let _ = Reflect::set(o, &JsValue::from_str(key), &value);
    }
}

/// `v[key]` (undefined when `v` has no such property).
pub(crate) fn get(v: &JsValue, key: &str, path: &str) -> Result<JsValue, OvError> {
    if !v.is_object() {
        return Err(bad(path, "an object"));
    }
    Reflect::get(v, &JsValue::from_str(key)).map_err(|_| bad(path, "a readable object"))
}

/// Reads field `key` of object `v` as `T`.
pub(crate) fn field<T: FromJs>(v: &JsValue, key: &str, path: &str) -> Result<T, OvError> {
    let f = get(v, key, path)?;
    T::from_js(&f, &format!("{path}.{key}"))
}

/// Reads a JS argument (for parameters typed as records in the `.d.ts`).
pub(crate) fn arg<T: FromJs>(v: &JsValue, name: &str) -> Result<T, OvError> {
    T::from_js(v, name)
}

fn is_nullish(v: &JsValue) -> bool {
    v.is_undefined() || v.is_null()
}

// ------------------------------------------------------------------------------- primitives

impl ToJs for String {
    fn to_js(&self) -> JsValue {
        JsValue::from_str(self)
    }
}
impl FromJs for String {
    fn from_js(v: &JsValue, path: &str) -> Result<Self, OvError> {
        v.as_string().ok_or_else(|| bad(path, "a string"))
    }
}
impl Elem for String {}

impl ToJs for bool {
    fn to_js(&self) -> JsValue {
        JsValue::from_bool(*self)
    }
}
impl FromJs for bool {
    fn from_js(v: &JsValue, path: &str) -> Result<Self, OvError> {
        v.as_bool().ok_or_else(|| bad(path, "a boolean"))
    }
}

/// The largest integer a JS number holds exactly (2^53 - 1).
pub(crate) const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

/// A JS number that is an integer in `[min, max]`.
pub(crate) fn int(v: &JsValue, path: &str, min: f64, max: f64) -> Result<f64, OvError> {
    match v.as_f64() {
        Some(n) if n.fract() == 0.0 && n >= min && n <= max => Ok(n),
        _ => Err(bad(path, &format!("an integer in {min}..={max}"))),
    }
}

macro_rules! int_impl {
    ($($t:ty => $min:expr, $max:expr;)*) => {$(
        impl ToJs for $t {
            // Values above 2^53 lose precision as a JS number. None of the facade's integers get
            // there (sizes, revisions, Unix milliseconds).
            #[allow(clippy::cast_precision_loss)]
            fn to_js(&self) -> JsValue {
                JsValue::from_f64(*self as f64)
            }
        }
        impl FromJs for $t {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            fn from_js(v: &JsValue, path: &str) -> Result<Self, OvError> {
                int(v, path, $min, $max).map(|n| n as $t)
            }
        }
    )*};
}

int_impl! {
    u16 => 0.0, 65_535.0;
    u32 => 0.0, 4_294_967_295.0;
    u64 => 0.0, MAX_SAFE;
    i64 => -MAX_SAFE, MAX_SAFE;
}
impl Elem for u32 {}

impl ToJs for Vec<u8> {
    fn to_js(&self) -> JsValue {
        Uint8Array::from(self.as_slice()).into()
    }
}
impl FromJs for Vec<u8> {
    fn from_js(v: &JsValue, path: &str) -> Result<Self, OvError> {
        v.dyn_ref::<Uint8Array>().map(Uint8Array::to_vec).ok_or_else(|| bad(path, "a Uint8Array"))
    }
}
impl Elem for Vec<u8> {}

impl<T: ToJs> ToJs for Option<T> {
    fn to_js(&self) -> JsValue {
        match self {
            Some(v) => v.to_js(),
            None => JsValue::UNDEFINED,
        }
    }
}
impl<T: FromJs> FromJs for Option<T> {
    fn from_js(v: &JsValue, path: &str) -> Result<Self, OvError> {
        if is_nullish(v) {
            Ok(None)
        } else {
            T::from_js(v, path).map(Some)
        }
    }
}

impl<T: Elem> ToJs for Vec<T> {
    fn to_js(&self) -> JsValue {
        self.iter().map(ToJs::to_js).collect::<Array>().into()
    }
}
impl<T: Elem> FromJs for Vec<T> {
    fn from_js(v: &JsValue, path: &str) -> Result<Self, OvError> {
        let a = v.dyn_ref::<Array>().ok_or_else(|| bad(path, "an array"))?;
        a.iter().enumerate().map(|(i, e)| T::from_js(&e, &format!("{path}[{i}]"))).collect()
    }
}

/// Header pairs: `[name, value]`.
impl ToJs for (String, String) {
    fn to_js(&self) -> JsValue {
        Array::of2(&self.0.to_js(), &self.1.to_js()).into()
    }
}
impl FromJs for (String, String) {
    fn from_js(v: &JsValue, path: &str) -> Result<Self, OvError> {
        let a = v.dyn_ref::<Array>().filter(|a| a.length() == 2).ok_or_else(|| bad(path, "a [name, value] pair"))?;
        Ok((String::from_js(&a.get(0), path)?, String::from_js(&a.get(1), path)?))
    }
}
impl Elem for (String, String) {}

// ------------------------------------------------------------------------------------ macros

/// A plain record: `record!(Rust::Path => TsName { rust_field: jsKey "?: ts type", ... })`.
///
/// The literal after the JS key is the rest of the TypeScript property (`": string"` or
/// `"?: string"`). Implements `ToJs`, `FromJs` and `Elem`, and emits `export interface TsName`.
macro_rules! record {
    ($ty:path => $name:ident { $($f:ident : $js:ident $ts:literal),* $(,)? }) => {
        impl $crate::convert::ToJs for $ty {
            fn to_js(&self) -> ::wasm_bindgen::JsValue {
                let o = $crate::convert::obj();
                $( $crate::convert::set(&o, stringify!($js), $crate::convert::ToJs::to_js(&self.$f)); )*
                o.into()
            }
        }
        impl $crate::convert::FromJs for $ty {
            fn from_js(v: &::wasm_bindgen::JsValue, path: &str) -> Result<Self, ::ov_error::OvError> {
                if !v.is_object() {
                    return Err($crate::convert::bad(path, concat!("a ", stringify!($name), " object")));
                }
                Ok(Self { $( $f: $crate::convert::field(v, stringify!($js), path)?, )* })
            }
        }
        impl $crate::convert::Elem for $ty {}
        #[::wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
        const _: &str = concat!(
            "export interface ", stringify!($name), " {\n",
            $( "  ", stringify!($js), $ts, ";\n", )*
            "}\n"
        );
    };
}

/// A fieldless enum as a string union: `unit_enum!(Rust::Path => TsName { Variant => "wire", ... })`.
macro_rules! unit_enum {
    ($ty:path => $name:ident { $v0:ident => $w0:literal $(, $v:ident => $w:literal)* $(,)? }) => {
        impl $crate::convert::ToJs for $ty {
            fn to_js(&self) -> ::wasm_bindgen::JsValue {
                use $ty as E;
                ::wasm_bindgen::JsValue::from_str(match self { E::$v0 => $w0, $( E::$v => $w, )* })
            }
        }
        impl $crate::convert::FromJs for $ty {
            fn from_js(v: &::wasm_bindgen::JsValue, path: &str) -> Result<Self, ::ov_error::OvError> {
                use $ty as E;
                match v.as_string().as_deref() {
                    Some($w0) => Ok(E::$v0),
                    $( Some($w) => Ok(E::$v), )*
                    _ => Err($crate::convert::bad(path, concat!("a ", stringify!($name), ": \"", $w0, "\"" $(, " | \"", $w, "\"")*))),
                }
            }
        }
        impl $crate::convert::Elem for $ty {}
        #[::wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
        const _: &str = concat!(
            "export type ", stringify!($name), " = \"", $w0, "\"", $( " | \"", $w, "\"", )* ";\n"
        );
    };
}

pub(crate) use {record, unit_enum};
