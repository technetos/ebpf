// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//
// THIS FILE IS AUTOGENERATED BY CARGO-LIBBPF-GEN!

pub use self::imp::*;

#[allow(dead_code)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(clippy::absolute_paths)]
#[allow(clippy::upper_case_acronyms)]
#[allow(clippy::zero_repeat_side_effects)]
#[warn(single_use_lifetimes)]
mod imp {
    #[allow(unused_imports)]
    use super::*;
    use libbpf_rs::libbpf_sys;
    use libbpf_rs::skel::OpenSkel;
    use libbpf_rs::skel::Skel;
    use libbpf_rs::skel::SkelBuilder;
    use libbpf_rs::AsRawLibbpf as _;
    use libbpf_rs::MapCore as _;
    fn build_skel_config(
    ) -> libbpf_rs::Result<libbpf_rs::__internal_skel::ObjectSkeletonConfig<'static>> {
        let mut builder = libbpf_rs::__internal_skel::ObjectSkeletonConfigBuilder::new(DATA);
        builder
            .name("interface_tap_bpf")
            .map("ringbuf", false)
            .map("interfac.rodata", false)
            .prog("read_from_interface");
        builder.build()
    }
    pub struct OpenInterfaceTapMaps<'obj> {
        pub ringbuf: libbpf_rs::OpenMapMut<'obj>,
        pub rodata: libbpf_rs::OpenMapMut<'obj>,
        _phantom: std::marker::PhantomData<&'obj ()>,
    }

    impl<'obj> OpenInterfaceTapMaps<'obj> {
        #[allow(unused_variables)]
        unsafe fn new(
            config: &libbpf_rs::__internal_skel::ObjectSkeletonConfig<'_>,
            object: &mut libbpf_rs::OpenObject,
        ) -> libbpf_rs::Result<Self> {
            let mut ringbuf = None;
            let mut rodata = None;
            let object = unsafe {
                std::mem::transmute::<&mut libbpf_rs::OpenObject, &'obj mut libbpf_rs::OpenObject>(
                    object,
                )
            };
            #[allow(clippy::never_loop)]
            for map in object.maps_mut() {
                let name = map.name().to_str().ok_or_else(|| {
                    libbpf_rs::Error::from(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "map has invalid name",
                    ))
                })?;
                #[allow(clippy::match_single_binding)]
                match name {
                    "ringbuf" => ringbuf = Some(map),
                    "interfac.rodata" => rodata = Some(map),
                    _ => panic!("encountered unexpected map: `{name}`"),
                }
            }

            let slf = Self {
                ringbuf: ringbuf.expect("map `ringbuf` not present"),
                rodata: rodata.expect("map `rodata` not present"),
                _phantom: std::marker::PhantomData,
            };
            Ok(slf)
        }
    }
    pub struct InterfaceTapMaps<'obj> {
        pub ringbuf: libbpf_rs::MapMut<'obj>,
        pub rodata: libbpf_rs::MapMut<'obj>,
        _phantom: std::marker::PhantomData<&'obj ()>,
    }

    impl<'obj> InterfaceTapMaps<'obj> {
        #[allow(unused_variables)]
        unsafe fn new(
            config: &libbpf_rs::__internal_skel::ObjectSkeletonConfig<'_>,
            object: &mut libbpf_rs::Object,
        ) -> libbpf_rs::Result<Self> {
            let mut ringbuf = None;
            let mut rodata = None;
            let object = unsafe {
                std::mem::transmute::<&mut libbpf_rs::Object, &'obj mut libbpf_rs::Object>(object)
            };
            #[allow(clippy::never_loop)]
            for map in object.maps_mut() {
                let name = map.name().to_str().ok_or_else(|| {
                    libbpf_rs::Error::from(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "map has invalid name",
                    ))
                })?;
                #[allow(clippy::match_single_binding)]
                match name {
                    "ringbuf" => ringbuf = Some(map),
                    "interfac.rodata" => rodata = Some(map),
                    _ => panic!("encountered unexpected map: `{name}`"),
                }
            }

            let slf = Self {
                ringbuf: ringbuf.expect("map `ringbuf` not present"),
                rodata: rodata.expect("map `rodata` not present"),
                _phantom: std::marker::PhantomData,
            };
            Ok(slf)
        }
    }
    pub struct OpenInterfaceTapProgs<'obj> {
        pub read_from_interface: libbpf_rs::OpenProgramMut<'obj>,
        _phantom: std::marker::PhantomData<&'obj ()>,
    }

    impl<'obj> OpenInterfaceTapProgs<'obj> {
        unsafe fn new(object: &mut libbpf_rs::OpenObject) -> libbpf_rs::Result<Self> {
            let mut read_from_interface = None;
            let object = unsafe {
                std::mem::transmute::<&mut libbpf_rs::OpenObject, &'obj mut libbpf_rs::OpenObject>(
                    object,
                )
            };
            for prog in object.progs_mut() {
                let name = prog.name().to_str().ok_or_else(|| {
                    libbpf_rs::Error::from(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "prog has invalid name",
                    ))
                })?;
                match name {
                    "read_from_interface" => read_from_interface = Some(prog),
                    _ => panic!("encountered unexpected prog: `{name}`"),
                }
            }

            let slf = Self {
                read_from_interface: read_from_interface
                    .expect("prog `read_from_interface` not present"),
                _phantom: std::marker::PhantomData,
            };
            Ok(slf)
        }
    }
    pub struct InterfaceTapProgs<'obj> {
        pub read_from_interface: libbpf_rs::ProgramMut<'obj>,
        _phantom: std::marker::PhantomData<&'obj ()>,
    }

    impl<'obj> InterfaceTapProgs<'obj> {
        #[allow(unused_variables)]
        fn new(open_progs: OpenInterfaceTapProgs<'obj>) -> Self {
            Self {
                read_from_interface: unsafe {
                    libbpf_rs::ProgramMut::new_mut(
                        open_progs.read_from_interface.as_libbpf_object().as_mut(),
                    )
                },
                _phantom: std::marker::PhantomData,
            }
        }
    }
    struct OwnedRef<'obj, O> {
        object: Option<&'obj mut std::mem::MaybeUninit<O>>,
    }

    impl<'obj, O> OwnedRef<'obj, O> {
        /// # Safety
        /// The object has to be initialized.
        unsafe fn new(object: &'obj mut std::mem::MaybeUninit<O>) -> Self {
            Self {
                object: Some(object),
            }
        }

        fn as_ref(&self) -> &O {
            // SAFETY: As per the contract during construction, the
            //         object has to be initialized.
            unsafe { self.object.as_ref().unwrap().assume_init_ref() }
        }

        fn as_mut(&mut self) -> &mut O {
            // SAFETY: As per the contract during construction, the
            //         object has to be initialized.
            unsafe { self.object.as_mut().unwrap().assume_init_mut() }
        }

        fn take(mut self) -> &'obj mut std::mem::MaybeUninit<O> {
            self.object.take().unwrap()
        }
    }

    impl<O> Drop for OwnedRef<'_, O> {
        fn drop(&mut self) {
            if let Some(object) = &mut self.object {
                unsafe { object.assume_init_drop() }
            }
        }
    }

    #[derive(Default)]
    pub struct InterfaceTapSkelBuilder {
        pub obj_builder: libbpf_rs::ObjectBuilder,
    }

    impl<'obj> InterfaceTapSkelBuilder {
        fn open_opts_impl(
            self,
            open_opts: *const libbpf_sys::bpf_object_open_opts,
            object: &'obj mut std::mem::MaybeUninit<libbpf_rs::OpenObject>,
        ) -> libbpf_rs::Result<OpenInterfaceTapSkel<'obj>> {
            let skel_config = build_skel_config()?;
            let skel_ptr = skel_config.as_libbpf_object();

            let ret =
                unsafe { libbpf_sys::bpf_object__open_skeleton(skel_ptr.as_ptr(), open_opts) };
            if ret != 0 {
                return Err(libbpf_rs::Error::from_raw_os_error(-ret));
            }

            // SAFETY: `skel_ptr` points to a valid object after the
            //         open call.
            let obj_ptr = unsafe { *skel_ptr.as_ref().obj };
            // SANITY: `bpf_object__open_skeleton` should have
            //         allocated the object.
            let obj_ptr = std::ptr::NonNull::new(obj_ptr).unwrap();
            // SAFETY: `obj_ptr` points to an opened object after
            //         skeleton open.
            let obj = unsafe { libbpf_rs::OpenObject::from_ptr(obj_ptr) };
            let _obj = object.write(obj);
            // SAFETY: We just wrote initialized data to `object`.
            let mut obj_ref = unsafe { OwnedRef::new(object) };

            #[allow(unused_mut)]
            let mut skel = OpenInterfaceTapSkel {
                maps: unsafe { OpenInterfaceTapMaps::new(&skel_config, obj_ref.as_mut())? },
                progs: unsafe { OpenInterfaceTapProgs::new(obj_ref.as_mut())? },
                obj: obj_ref,
                // SAFETY: Our `struct_ops` type contains only pointers,
                //         which are allowed to be NULL.
                // TODO: Generate and use a `Default` representation
                //       instead, to cut down on unsafe code.
                struct_ops: unsafe { std::mem::zeroed() },
                skel_config,
            };

            Ok(skel)
        }
    }

    impl<'obj> SkelBuilder<'obj> for InterfaceTapSkelBuilder {
        type Output = OpenInterfaceTapSkel<'obj>;
        fn open(
            self,
            object: &'obj mut std::mem::MaybeUninit<libbpf_rs::OpenObject>,
        ) -> libbpf_rs::Result<OpenInterfaceTapSkel<'obj>> {
            self.open_opts_impl(std::ptr::null(), object)
        }

        fn open_opts(
            self,
            open_opts: libbpf_sys::bpf_object_open_opts,
            object: &'obj mut std::mem::MaybeUninit<libbpf_rs::OpenObject>,
        ) -> libbpf_rs::Result<OpenInterfaceTapSkel<'obj>> {
            self.open_opts_impl(&open_opts, object)
        }

        fn object_builder(&self) -> &libbpf_rs::ObjectBuilder {
            &self.obj_builder
        }
        fn object_builder_mut(&mut self) -> &mut libbpf_rs::ObjectBuilder {
            &mut self.obj_builder
        }
    }

    #[derive(Debug, Clone)]
    #[repr(C)]
    pub struct StructOps {}

    impl StructOps {}
    pub mod types {
        #[allow(unused_imports)]
        use super::*;
        #[derive(Debug, Copy, Clone)]
        #[repr(C)]
        pub struct __anon_1 {
            pub r#type: *mut [i32; 27],
            pub max_entries: *mut [i32; 4096],
        }
        impl Default for __anon_1 {
            fn default() -> Self {
                Self {
                    r#type: std::ptr::null_mut(),
                    max_entries: std::ptr::null_mut(),
                }
            }
        }
        #[derive(Debug, Default, Copy, Clone)]
        #[repr(C)]
        pub struct xdp_md {
            pub data: u32,
            pub data_end: u32,
            pub data_meta: u32,
            pub ingress_ifindex: u32,
            pub rx_queue_index: u32,
            pub egress_ifindex: u32,
        }
        #[derive(Debug, Default, Copy, Clone)]
        #[repr(C)]
        pub struct ethhdr {
            pub h_dest: [u8; 6],
            pub h_source: [u8; 6],
            pub h_proto: u16,
        }
        #[derive(Debug, Default, Copy, Clone)]
        #[repr(C)]
        pub struct iphdr {
            pub __pad_0: [u8; 1],
            pub tos: u8,
            pub tot_len: u16,
            pub id: u16,
            pub frag_off: u16,
            pub ttl: u8,
            pub protocol: u8,
            pub check: u16,
            pub __anon_2: __anon_2,
        }
        #[derive(Copy, Clone)]
        #[repr(C)]
        pub union __anon_2 {
            pub __anon_3: __anon_3,
            pub addrs: __anon_3,
        }
        impl std::fmt::Debug for __anon_2 {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "(???)")
            }
        }
        impl Default for __anon_2 {
            fn default() -> Self {
                Self {
                    __anon_3: __anon_3::default(),
                }
            }
        }
        #[derive(Debug, Default, Copy, Clone)]
        #[repr(C)]
        pub struct __anon_3 {
            pub saddr: u32,
            pub daddr: u32,
        }
        #[derive(Debug, Default, Copy, Clone)]
        #[repr(C)]
        pub struct udphdr {
            pub source: u16,
            pub dest: u16,
            pub len: u16,
            pub check: u16,
        }
        #[derive(Debug, Copy, Clone)]
        #[repr(C)]
        pub struct rodata {}
        #[derive(Debug, Copy, Clone)]
        #[repr(C)]
        pub struct maps {
            pub ringbuf: __anon_1,
        }
        #[derive(Debug, Copy, Clone)]
        #[repr(C)]
        pub struct license {
            pub _license: [i8; 4],
        }
    }
    pub struct OpenInterfaceTapSkel<'obj> {
        obj: OwnedRef<'obj, libbpf_rs::OpenObject>,
        pub maps: OpenInterfaceTapMaps<'obj>,
        pub progs: OpenInterfaceTapProgs<'obj>,
        pub struct_ops: StructOps,
        skel_config: libbpf_rs::__internal_skel::ObjectSkeletonConfig<'obj>,
    }

    impl<'obj> OpenSkel<'obj> for OpenInterfaceTapSkel<'obj> {
        type Output = InterfaceTapSkel<'obj>;
        fn load(self) -> libbpf_rs::Result<InterfaceTapSkel<'obj>> {
            let skel_ptr = self.skel_config.as_libbpf_object().as_ptr();

            let ret = unsafe { libbpf_sys::bpf_object__load_skeleton(skel_ptr) };
            if ret != 0 {
                return Err(libbpf_rs::Error::from_raw_os_error(-ret));
            }

            let obj_ref = self.obj.take();
            let open_obj = std::mem::replace(obj_ref, std::mem::MaybeUninit::uninit());
            // SAFETY: `open_obj` is guaranteed to be properly
            //         initialized as it came from an `OwnedRef`.
            let obj_ptr = unsafe { open_obj.assume_init().take_ptr() };
            // SAFETY: `obj_ptr` points to a loaded object after
            //         skeleton load.
            let obj = unsafe { libbpf_rs::Object::from_ptr(obj_ptr) };
            // SAFETY: `OpenObject` and `Object` are guaranteed to
            //         have the same memory layout.
            let obj_ref = unsafe {
                std::mem::transmute::<
                    &'obj mut std::mem::MaybeUninit<libbpf_rs::OpenObject>,
                    &'obj mut std::mem::MaybeUninit<libbpf_rs::Object>,
                >(obj_ref)
            };
            let _obj = obj_ref.write(obj);
            // SAFETY: We just wrote initialized data to `obj_ref`.
            let mut obj_ref = unsafe { OwnedRef::new(obj_ref) };

            Ok(InterfaceTapSkel {
                maps: unsafe { InterfaceTapMaps::new(&self.skel_config, obj_ref.as_mut())? },
                progs: InterfaceTapProgs::new(self.progs),
                obj: obj_ref,
                struct_ops: self.struct_ops,
                skel_config: self.skel_config,
                links: InterfaceTapLinks::default(),
            })
        }

        fn open_object(&self) -> &libbpf_rs::OpenObject {
            self.obj.as_ref()
        }

        fn open_object_mut(&mut self) -> &mut libbpf_rs::OpenObject {
            self.obj.as_mut()
        }
    }
    #[derive(Default)]
    pub struct InterfaceTapLinks {
        pub read_from_interface: Option<libbpf_rs::Link>,
    }
    pub struct InterfaceTapSkel<'obj> {
        obj: OwnedRef<'obj, libbpf_rs::Object>,
        pub maps: InterfaceTapMaps<'obj>,
        pub progs: InterfaceTapProgs<'obj>,
        struct_ops: StructOps,
        skel_config: libbpf_rs::__internal_skel::ObjectSkeletonConfig<'obj>,
        pub links: InterfaceTapLinks,
    }

    unsafe impl Send for InterfaceTapSkel<'_> {}
    unsafe impl Sync for InterfaceTapSkel<'_> {}

    impl<'obj> Skel<'obj> for InterfaceTapSkel<'obj> {
        fn object(&self) -> &libbpf_rs::Object {
            self.obj.as_ref()
        }

        fn object_mut(&mut self) -> &mut libbpf_rs::Object {
            self.obj.as_mut()
        }
        fn attach(&mut self) -> libbpf_rs::Result<()> {
            let skel_ptr = self.skel_config.as_libbpf_object().as_ptr();
            let ret = unsafe { libbpf_sys::bpf_object__attach_skeleton(skel_ptr) };
            if ret != 0 {
                return Err(libbpf_rs::Error::from_raw_os_error(-ret));
            }

            self.links = InterfaceTapLinks {
                read_from_interface: core::ptr::NonNull::new(self.skel_config.prog_link_ptr(0)?)
                    .map(|ptr| unsafe { libbpf_rs::Link::from_ptr(ptr) }),
            };

            Ok(())
        }
    }
    impl InterfaceTapSkel<'_> {
        pub fn struct_ops_raw(&self) -> *const StructOps {
            &self.struct_ops
        }

        pub fn struct_ops(&self) -> &StructOps {
            &self.struct_ops
        }
    }
    const DATA: &[u8] = &[
        127, 69, 76, 70, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 247, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 184, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0,
        0, 64, 0, 10, 0, 1, 0, 0, 46, 115, 116, 114, 116, 97, 98, 0, 46, 115, 121, 109, 116, 97,
        98, 0, 120, 100, 112, 0, 46, 114, 111, 100, 97, 116, 97, 0, 46, 109, 97, 112, 115, 0, 108,
        105, 99, 101, 110, 115, 101, 0, 105, 110, 116, 101, 114, 102, 97, 99, 101, 95, 116, 97,
        112, 46, 98, 112, 102, 46, 99, 0, 76, 66, 66, 48, 95, 50, 0, 114, 101, 97, 100, 95, 102,
        114, 111, 109, 95, 105, 110, 116, 101, 114, 102, 97, 99, 101, 46, 95, 95, 95, 95, 102, 109,
        116, 0, 76, 66, 66, 48, 95, 53, 0, 114, 101, 97, 100, 95, 102, 114, 111, 109, 95, 105, 110,
        116, 101, 114, 102, 97, 99, 101, 0, 114, 105, 110, 103, 98, 117, 102, 0, 95, 108, 105, 99,
        101, 110, 115, 101, 0, 46, 114, 101, 108, 120, 100, 112, 0, 46, 66, 84, 70, 0, 46, 66, 84,
        70, 46, 101, 120, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 43, 0, 0, 0, 4, 0, 241, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 3, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 63, 0, 0, 0, 0,
        0, 3, 0, 88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 70, 0, 0, 0, 1, 0, 4, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 43, 0, 0, 0, 0, 0, 0, 0, 98, 0, 0, 0, 0, 0, 3, 0, 72, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 105, 0, 0, 0, 18, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 1, 0, 0, 0, 0, 0, 0, 125, 0, 0,
        0, 17, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 133, 0, 0, 0, 17, 0, 6, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 97, 18, 0, 0, 0, 0, 0, 0, 191, 36, 0, 0, 0,
        0, 0, 0, 7, 4, 0, 0, 42, 0, 0, 0, 97, 17, 4, 0, 0, 0, 0, 0, 61, 65, 6, 0, 0, 0, 0, 0, 24,
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 183, 2, 0, 0, 43, 0, 0, 0, 133, 0, 0, 0, 6, 0,
        0, 0, 183, 0, 0, 0, 2, 0, 0, 0, 149, 0, 0, 0, 0, 0, 0, 0, 105, 33, 12, 0, 0, 0, 0, 0, 85,
        1, 252, 255, 8, 0, 0, 0, 191, 33, 0, 0, 0, 0, 0, 0, 7, 1, 0, 0, 14, 0, 0, 0, 113, 17, 9, 0,
        0, 0, 0, 0, 85, 1, 248, 255, 17, 0, 0, 0, 7, 2, 0, 0, 34, 0, 0, 0, 105, 35, 4, 0, 0, 0, 0,
        0, 123, 74, 248, 255, 0, 0, 0, 0, 220, 3, 0, 0, 16, 0, 0, 0, 24, 1, 0, 0, 248, 255, 255,
        255, 0, 0, 0, 0, 0, 0, 0, 0, 15, 19, 0, 0, 0, 0, 0, 0, 103, 3, 0, 0, 32, 0, 0, 0, 119, 3,
        0, 0, 32, 0, 0, 0, 191, 162, 0, 0, 0, 0, 0, 0, 7, 2, 0, 0, 248, 255, 255, 255, 24, 1, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 183, 4, 0, 0, 0, 0, 0, 0, 133, 0, 0, 0, 130, 0, 0, 0,
        5, 0, 232, 255, 0, 0, 0, 0, 66, 111, 117, 110, 100, 115, 32, 99, 104, 101, 99, 107, 32,
        102, 97, 105, 108, 101, 100, 44, 32, 112, 111, 105, 110, 116, 101, 114, 32, 112, 97, 115,
        116, 32, 100, 97, 116, 97, 95, 101, 110, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 71, 80, 76, 0, 0, 0, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 6, 0,
        0, 0, 224, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 8, 0, 0, 0, 159, 235, 1, 0, 24, 0, 0, 0, 0, 0,
        0, 0, 152, 3, 0, 0, 152, 3, 0, 0, 237, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 0, 0, 0, 1, 0,
        0, 0, 0, 0, 0, 1, 4, 0, 0, 0, 32, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 2, 0, 0, 0,
        4, 0, 0, 0, 27, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 1, 4, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 2, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 0, 16, 0, 0,
        0, 0, 0, 0, 2, 0, 0, 4, 16, 0, 0, 0, 25, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 30, 0, 0, 0, 5,
        0, 0, 0, 64, 0, 0, 0, 42, 0, 0, 0, 0, 0, 0, 14, 7, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 2, 10, 0, 0, 0, 50, 0, 0, 0, 6, 0, 0, 4, 24, 0, 0, 0, 57, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0,
        0, 62, 0, 0, 0, 11, 0, 0, 0, 32, 0, 0, 0, 71, 0, 0, 0, 11, 0, 0, 0, 64, 0, 0, 0, 81, 0, 0,
        0, 11, 0, 0, 0, 96, 0, 0, 0, 97, 0, 0, 0, 11, 0, 0, 0, 128, 0, 0, 0, 112, 0, 0, 0, 11, 0,
        0, 0, 160, 0, 0, 0, 127, 0, 0, 0, 0, 0, 0, 8, 12, 0, 0, 0, 133, 0, 0, 0, 0, 0, 0, 1, 4, 0,
        0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 13, 2, 0, 0, 0, 146, 0, 0, 0, 9, 0, 0, 0, 150, 0,
        0, 0, 1, 0, 0, 12, 13, 0, 0, 0, 170, 0, 0, 0, 3, 0, 0, 4, 14, 0, 0, 0, 177, 0, 0, 0, 17, 0,
        0, 0, 0, 0, 0, 0, 184, 0, 0, 0, 17, 0, 0, 0, 48, 0, 0, 0, 193, 0, 0, 0, 18, 0, 0, 0, 96, 0,
        0, 0, 201, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0,
        16, 0, 0, 0, 4, 0, 0, 0, 6, 0, 0, 0, 215, 0, 0, 0, 0, 0, 0, 8, 19, 0, 0, 0, 222, 0, 0, 0,
        0, 0, 0, 8, 20, 0, 0, 0, 228, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 16, 0, 0, 0, 243, 0, 0, 0,
        10, 0, 0, 132, 20, 0, 0, 0, 249, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 4, 253, 0, 0, 0, 22, 0, 0,
        0, 4, 0, 0, 4, 5, 1, 0, 0, 22, 0, 0, 0, 8, 0, 0, 0, 9, 1, 0, 0, 18, 0, 0, 0, 16, 0, 0, 0,
        17, 1, 0, 0, 18, 0, 0, 0, 32, 0, 0, 0, 20, 1, 0, 0, 18, 0, 0, 0, 48, 0, 0, 0, 29, 1, 0, 0,
        22, 0, 0, 0, 64, 0, 0, 0, 33, 1, 0, 0, 22, 0, 0, 0, 72, 0, 0, 0, 42, 1, 0, 0, 23, 0, 0, 0,
        80, 0, 0, 0, 0, 0, 0, 0, 24, 0, 0, 0, 96, 0, 0, 0, 48, 1, 0, 0, 0, 0, 0, 8, 16, 0, 0, 0,
        53, 1, 0, 0, 0, 0, 0, 8, 19, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 5, 8, 0, 0, 0, 0, 0, 0, 0, 25,
        0, 0, 0, 0, 0, 0, 0, 61, 1, 0, 0, 25, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 4, 8, 0, 0,
        0, 67, 1, 0, 0, 26, 0, 0, 0, 0, 0, 0, 0, 73, 1, 0, 0, 26, 0, 0, 0, 32, 0, 0, 0, 79, 1, 0,
        0, 0, 0, 0, 8, 11, 0, 0, 0, 86, 1, 0, 0, 4, 0, 0, 4, 8, 0, 0, 0, 93, 1, 0, 0, 18, 0, 0, 0,
        0, 0, 0, 0, 100, 1, 0, 0, 18, 0, 0, 0, 16, 0, 0, 0, 105, 1, 0, 0, 18, 0, 0, 0, 32, 0, 0, 0,
        42, 1, 0, 0, 23, 0, 0, 0, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 29, 0, 0, 0, 109, 1, 0, 0,
        0, 0, 0, 1, 1, 0, 0, 0, 8, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 28, 0, 0, 0, 4, 0,
        0, 0, 43, 0, 0, 0, 114, 1, 0, 0, 0, 0, 0, 14, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        3, 0, 0, 0, 0, 29, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 142, 1, 0, 0, 0, 0, 0, 14, 32, 0, 0, 0,
        1, 0, 0, 0, 211, 3, 0, 0, 1, 0, 0, 15, 43, 0, 0, 0, 31, 0, 0, 0, 0, 0, 0, 0, 43, 0, 0, 0,
        219, 3, 0, 0, 1, 0, 0, 15, 16, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 225, 3, 0, 0,
        1, 0, 0, 15, 4, 0, 0, 0, 33, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 105, 110, 116, 0, 95, 95,
        65, 82, 82, 65, 89, 95, 83, 73, 90, 69, 95, 84, 89, 80, 69, 95, 95, 0, 116, 121, 112, 101,
        0, 109, 97, 120, 95, 101, 110, 116, 114, 105, 101, 115, 0, 114, 105, 110, 103, 98, 117,
        102, 0, 120, 100, 112, 95, 109, 100, 0, 100, 97, 116, 97, 0, 100, 97, 116, 97, 95, 101,
        110, 100, 0, 100, 97, 116, 97, 95, 109, 101, 116, 97, 0, 105, 110, 103, 114, 101, 115, 115,
        95, 105, 102, 105, 110, 100, 101, 120, 0, 114, 120, 95, 113, 117, 101, 117, 101, 95, 105,
        110, 100, 101, 120, 0, 101, 103, 114, 101, 115, 115, 95, 105, 102, 105, 110, 100, 101, 120,
        0, 95, 95, 117, 51, 50, 0, 117, 110, 115, 105, 103, 110, 101, 100, 32, 105, 110, 116, 0,
        99, 116, 120, 0, 114, 101, 97, 100, 95, 102, 114, 111, 109, 95, 105, 110, 116, 101, 114,
        102, 97, 99, 101, 0, 101, 116, 104, 104, 100, 114, 0, 104, 95, 100, 101, 115, 116, 0, 104,
        95, 115, 111, 117, 114, 99, 101, 0, 104, 95, 112, 114, 111, 116, 111, 0, 117, 110, 115,
        105, 103, 110, 101, 100, 32, 99, 104, 97, 114, 0, 95, 95, 98, 101, 49, 54, 0, 95, 95, 117,
        49, 54, 0, 117, 110, 115, 105, 103, 110, 101, 100, 32, 115, 104, 111, 114, 116, 0, 105,
        112, 104, 100, 114, 0, 105, 104, 108, 0, 118, 101, 114, 115, 105, 111, 110, 0, 116, 111,
        115, 0, 116, 111, 116, 95, 108, 101, 110, 0, 105, 100, 0, 102, 114, 97, 103, 95, 111, 102,
        102, 0, 116, 116, 108, 0, 112, 114, 111, 116, 111, 99, 111, 108, 0, 99, 104, 101, 99, 107,
        0, 95, 95, 117, 56, 0, 95, 95, 115, 117, 109, 49, 54, 0, 97, 100, 100, 114, 115, 0, 115,
        97, 100, 100, 114, 0, 100, 97, 100, 100, 114, 0, 95, 95, 98, 101, 51, 50, 0, 117, 100, 112,
        104, 100, 114, 0, 115, 111, 117, 114, 99, 101, 0, 100, 101, 115, 116, 0, 108, 101, 110, 0,
        99, 104, 97, 114, 0, 114, 101, 97, 100, 95, 102, 114, 111, 109, 95, 105, 110, 116, 101,
        114, 102, 97, 99, 101, 46, 95, 95, 95, 95, 102, 109, 116, 0, 95, 108, 105, 99, 101, 110,
        115, 101, 0, 47, 117, 115, 101, 114, 100, 97, 116, 97, 47, 98, 112, 102, 47, 105, 110, 116,
        101, 114, 102, 97, 99, 101, 95, 116, 97, 112, 47, 115, 114, 99, 47, 98, 112, 102, 47, 105,
        110, 116, 101, 114, 102, 97, 99, 101, 95, 116, 97, 112, 46, 98, 112, 102, 46, 99, 0, 32,
        32, 118, 111, 105, 100, 32, 42, 100, 97, 116, 97, 32, 61, 32, 40, 118, 111, 105, 100, 32,
        42, 41, 40, 108, 111, 110, 103, 41, 99, 116, 120, 45, 62, 100, 97, 116, 97, 59, 0, 32, 32,
        105, 102, 32, 40, 100, 97, 116, 97, 32, 43, 32, 115, 105, 122, 101, 111, 102, 40, 42, 101,
        116, 104, 41, 32, 43, 32, 115, 105, 122, 101, 111, 102, 40, 42, 105, 112, 104, 41, 32, 43,
        32, 115, 105, 122, 101, 111, 102, 40, 42, 117, 100, 112, 41, 32, 62, 32, 100, 97, 116, 97,
        95, 101, 110, 100, 41, 32, 123, 0, 32, 32, 118, 111, 105, 100, 32, 42, 100, 97, 116, 97,
        95, 101, 110, 100, 32, 61, 32, 40, 118, 111, 105, 100, 32, 42, 41, 40, 108, 111, 110, 103,
        41, 99, 116, 120, 45, 62, 100, 97, 116, 97, 95, 101, 110, 100, 59, 0, 32, 32, 32, 32, 98,
        112, 102, 95, 112, 114, 105, 110, 116, 107, 40, 34, 66, 111, 117, 110, 100, 115, 32, 99,
        104, 101, 99, 107, 32, 102, 97, 105, 108, 101, 100, 44, 32, 112, 111, 105, 110, 116, 101,
        114, 32, 112, 97, 115, 116, 32, 100, 97, 116, 97, 95, 101, 110, 100, 34, 41, 59, 0, 125, 0,
        32, 32, 105, 102, 32, 40, 101, 116, 104, 45, 62, 104, 95, 112, 114, 111, 116, 111, 32, 33,
        61, 32, 98, 112, 102, 95, 104, 116, 111, 110, 115, 40, 69, 84, 72, 95, 80, 95, 73, 80, 41,
        41, 32, 123, 0, 32, 32, 105, 102, 32, 40, 105, 112, 104, 45, 62, 112, 114, 111, 116, 111,
        99, 111, 108, 32, 61, 61, 32, 73, 80, 80, 82, 79, 84, 79, 95, 85, 68, 80, 41, 32, 123, 0,
        32, 32, 32, 32, 117, 110, 115, 105, 103, 110, 101, 100, 32, 105, 110, 116, 32, 112, 97,
        121, 108, 111, 97, 100, 95, 115, 105, 122, 101, 32, 61, 32, 98, 112, 102, 95, 110, 116,
        111, 104, 115, 40, 117, 100, 112, 45, 62, 108, 101, 110, 41, 32, 45, 32, 115, 105, 122,
        101, 111, 102, 40, 42, 117, 100, 112, 41, 59, 0, 32, 32, 32, 32, 117, 110, 115, 105, 103,
        110, 101, 100, 32, 99, 104, 97, 114, 32, 42, 112, 97, 121, 108, 111, 97, 100, 32, 61, 32,
        40, 117, 110, 115, 105, 103, 110, 101, 100, 32, 99, 104, 97, 114, 32, 42, 41, 117, 100,
        112, 32, 43, 32, 115, 105, 122, 101, 111, 102, 40, 42, 117, 100, 112, 41, 59, 0, 32, 32,
        32, 32, 98, 112, 102, 95, 114, 105, 110, 103, 98, 117, 102, 95, 111, 117, 116, 112, 117,
        116, 40, 38, 114, 105, 110, 103, 98, 117, 102, 44, 32, 38, 112, 97, 121, 108, 111, 97, 100,
        44, 32, 112, 97, 121, 108, 111, 97, 100, 95, 115, 105, 122, 101, 44, 32, 48, 41, 59, 0, 48,
        58, 48, 0, 48, 58, 49, 0, 48, 58, 50, 0, 48, 58, 55, 0, 46, 114, 111, 100, 97, 116, 97, 0,
        46, 109, 97, 112, 115, 0, 108, 105, 99, 101, 110, 115, 101, 0, 120, 100, 112, 0, 0, 0, 0,
        159, 235, 1, 0, 32, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 20, 0, 0, 0, 60, 1, 0, 0, 80, 1, 0,
        0, 92, 0, 0, 0, 8, 0, 0, 0, 233, 3, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 14, 0, 0, 0, 16, 0, 0, 0,
        233, 3, 0, 0, 19, 0, 0, 0, 0, 0, 0, 0, 151, 1, 0, 0, 207, 1, 0, 0, 35, 56, 0, 0, 8, 0, 0,
        0, 151, 1, 0, 0, 247, 1, 0, 0, 42, 84, 0, 0, 24, 0, 0, 0, 151, 1, 0, 0, 61, 2, 0, 0, 39,
        60, 0, 0, 32, 0, 0, 0, 151, 1, 0, 0, 247, 1, 0, 0, 7, 84, 0, 0, 40, 0, 0, 0, 151, 1, 0, 0,
        109, 2, 0, 0, 5, 88, 0, 0, 72, 0, 0, 0, 151, 1, 0, 0, 171, 2, 0, 0, 1, 160, 0, 0, 88, 0, 0,
        0, 151, 1, 0, 0, 173, 2, 0, 0, 12, 104, 0, 0, 96, 0, 0, 0, 151, 1, 0, 0, 173, 2, 0, 0, 7,
        104, 0, 0, 104, 0, 0, 0, 151, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 120, 0, 0, 0, 151, 1, 0, 0,
        218, 2, 0, 0, 12, 120, 0, 0, 128, 0, 0, 0, 151, 1, 0, 0, 218, 2, 0, 0, 7, 120, 0, 0, 136,
        0, 0, 0, 151, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 144, 0, 0, 0, 151, 1, 0, 0, 0, 3, 0, 0, 33,
        128, 0, 0, 152, 0, 0, 0, 151, 1, 0, 0, 68, 3, 0, 0, 20, 136, 0, 0, 160, 0, 0, 0, 151, 1, 0,
        0, 0, 3, 0, 0, 33, 128, 0, 0, 184, 0, 0, 0, 151, 1, 0, 0, 0, 3, 0, 0, 53, 128, 0, 0, 192,
        0, 0, 0, 151, 1, 0, 0, 134, 3, 0, 0, 44, 144, 0, 0, 216, 0, 0, 0, 151, 1, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 224, 0, 0, 0, 151, 1, 0, 0, 134, 3, 0, 0, 5, 144, 0, 0, 16, 0, 0, 0, 233, 3, 0,
        0, 5, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 195, 3, 0, 0, 0, 0, 0, 0, 24, 0, 0, 0, 10, 0, 0, 0,
        199, 3, 0, 0, 0, 0, 0, 0, 88, 0, 0, 0, 15, 0, 0, 0, 203, 3, 0, 0, 0, 0, 0, 0, 120, 0, 0, 0,
        21, 0, 0, 0, 207, 3, 0, 0, 0, 0, 0, 0, 144, 0, 0, 0, 27, 0, 0, 0, 203, 3, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 164, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 232, 0, 0, 0, 0, 0, 0, 0, 240, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
        0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 1, 0, 0, 0, 6, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 216, 1, 0, 0, 0, 0, 0, 0, 8, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 21, 0, 0, 0, 1, 0, 0, 0,
        2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 224, 2, 0, 0, 0, 0, 0, 0, 43, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 29, 0, 0,
        0, 1, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 3, 0, 0, 0, 0, 0, 0, 16,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 35, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 3, 0, 0, 0,
        0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 142, 0, 0, 0, 9, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        40, 3, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 8, 0, 0, 0, 0, 0,
        0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 150, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 72, 3, 0, 0, 0, 0, 0, 0, 157, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 155, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 232, 10, 0, 0, 0, 0, 0, 0, 204, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
}
