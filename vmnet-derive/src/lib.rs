use darling::FromVariant;
use proc_macro::{self, TokenStream};
use proc_macro2::Ident;
use quote::{format_ident, quote};
use syn::spanned::Spanned;
use syn::Fields::Unnamed;
use syn::{parse_macro_input, DeriveInput, Error};

#[derive(FromVariant)]
#[darling(attributes(vmnet))]
struct Opts {
    ffi: Option<String>,
}

#[proc_macro_derive(Vmnet, attributes(vmnet))]
pub fn derive(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input);

    let input_enum = match input.data {
        syn::Data::Enum(input_enum) => input_enum,
        _ => {
            return Error::new(input.span(), "only enumerations are supported")
                .to_compile_error()
                .into()
        }
    };

    // Normally would equate to "Parameter"
    let input_enum_name = input.ident.clone();
    // Normally would equate to "ParameterKind"
    let kind_enum_name = format_ident!("{}Kind", input.ident);

    let mut kinds: Vec<Ident> = Vec::new();
    let mut kind_enum_to_vmnet_ffi_key_arms = Vec::new();
    let mut kind_enum_to_input_enum_arms = Vec::new();
    let mut input_enum_to_xpc_data_arms = Vec::new();
    let mut input_enum_to_kind_enum_arms = Vec::new();

    for input_variant in input_enum.variants {
        let unnamed = match input_variant.fields {
            Unnamed(ref unnamed) => &unnamed.unnamed,
            _ => {
                return Error::new(input_variant.span(), "only unnamed fields are supported")
                    .to_compile_error()
                    .into()
            }
        };

        if unnamed.len() > 1 {
            return Error::new(
                input_variant.span(),
                "there should be exactly one unnamed field",
            )
            .to_compile_error()
            .into();
        }

        let field = unnamed.first().unwrap();

        let typ = match &field.ty {
            syn::Type::Path(syn::TypePath { path, .. }) if path.is_ident("String") => {
                format_ident!("String")
            }
            syn::Type::Path(syn::TypePath { path, .. }) if path.is_ident("u64") => {
                format_ident!("Uint64")
            }
            syn::Type::Path(syn::TypePath { path, .. }) if path.is_ident("bool") => {
                format_ident!("Bool")
            }
            syn::Type::Path(syn::TypePath { path, .. }) if path.is_ident("Uuid") => {
                format_ident!("Uuid")
            }
            _ => {
                return Error::new(
                    input_variant.span(),
                    "unsupported unnamed field type (expected String, u64, bool or Uuid)",
                )
                .to_compile_error()
                .into();
            }
        };

        let opts: Opts = Opts::from_variant(&input_variant).unwrap();

        let vmnet_ffi_key = match opts.ffi {
            Some(ffi) => format_ident!("{}", ffi),
            None => {
                return Error::new(
                    input_variant.span(),
                    "missing #[vmnet(ffi = \"...\" attribute",
                )
                .to_compile_error()
                .into()
            }
        };

        let variant_name = format_ident!("{}", input_variant.ident);
        kinds.push(variant_name.clone());

        input_enum_to_kind_enum_arms.push(quote! {
            #input_enum_name::#variant_name(_) => { #kind_enum_name::#variant_name }
        });

        input_enum_to_xpc_data_arms.push(quote! {
            #input_enum_name::#variant_name(val) => { XpcData::from(val) }
        });

        kind_enum_to_vmnet_ffi_key_arms.push(quote! {
            #kind_enum_name::#variant_name => #vmnet_ffi_key
        });

        kind_enum_to_input_enum_arms.push(quote! {
            (#kind_enum_name::#variant_name, XpcData::#typ(val)) => { Some(#input_enum_name::#variant_name(val)) }
        });
    }

    let output = quote! {
        /// Parameter key (kind) useful for retrieving a specific parameter from the [`Parameters`](Parameters) dictionary.
        #[derive(Debug, Hash, Eq, PartialEq, Sequence)]
        pub enum #kind_enum_name {
            #(#kinds),*
        }

        impl From<&#input_enum_name> for #kind_enum_name {
            fn from(val: &#input_enum_name) -> Self {
                match val {
                    #(#input_enum_to_kind_enum_arms),*
                }
            }
        }

        impl From<#input_enum_name> for XpcData {
            fn from(val: #input_enum_name) -> Self {
                match val {
                    #(#input_enum_to_xpc_data_arms),*
                }
            }
        }

        impl #kind_enum_name {
            pub fn vmnet_ffi_key(&self) -> *const c_char {
                unsafe {
                    match self {
                        #(#kind_enum_to_vmnet_ffi_key_arms),*
                    }
                }
            }

            pub fn vmnet_key(&self) -> String {
                unsafe { CStr::from_ptr(self.vmnet_ffi_key()).to_string_lossy().to_string() }
            }

            fn parse(&self, value: XpcData) -> Option<#input_enum_name> {
                match (self, value) {
                    #(#kind_enum_to_input_enum_arms)*
                    _ => { None }
                }
            }
        }
    };

    output.into()
}
