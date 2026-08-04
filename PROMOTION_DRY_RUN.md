# Promotion dry run (F4b)

Every active monitored config, its tracking-plan state today, and what the
sweep would supply. `tiers after` is derived by the real enrollment classifier
(`event_topics.extract_governance_topics`) over the plan that would be read —
the promoted job artifact, or the existing materialization for rows already
current. `unst` counts specs recorded before the taxonomy existed: an absent
stamp, not a tier.

## Summary

```json
{
  "configs": 183,
  "contracts_gaining_topics": 94,
  "notify_rights_gains": 111,
  "notify_rights_gains_by_witness": {
    "canonical_family": 107,
    "old_new_args_single_writer": 4
  },
  "notify_rights_gains_unattributed": 0,
  "outcomes": {
    "already_current": 23,
    "job_plan_artifact_absent": 26,
    "job_schema_version_not_current": 1,
    "keccak_bound_to_other_address": 1,
    "no_completed_job": 25,
    "promotable": 107
  },
  "specs_by_tier_after": {
    "activity": 149,
    "hint": 209,
    "self_describing": 111
  },
  "specs_by_tier_before": {
    "unstamped": 145
  }
}
```

## Per-config

| address | chain | plan state before | outcome | plan supplied | tiers before | tiers after | notify gains |
|---|---|---|---|---|---|---|---|
| `0x04c0599ae5a44757c0af6f9ec3b93da8976c150a` | base | no_current_materialization | job_plan_artifact_absent | no | - | - | 0 |
| `0x05a1552c5e18f5a0bb9571b5f2d6a4765ebda32b` | base | no_current_materialization | promotable | yes | - | self=1 hint=11 | 1 |
| `0x1509b1fdd01caf9697aff514b9574b4a27173dd2` | base | no_current_materialization | promotable | yes | - | self=1 hint=3 acti=3 | 1 |
| `0x1f21ada3c59b81d7b1bcf5f80f4acfd31ba356e3` | base | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0x382d0106f308864d5462332d9d3bb54a60384b70` | base | no_current_materialization | promotable | yes | - | self=1 hint=2 | 1 |
| `0x3994741a5b29c60d0ab318de1024f9256fe959dc` | base | no_current_materialization | keccak_bound_to_other_address | no | - | - | 0 |
| `0x3d320286e014c3e1ce99af6d6b00f0c1d63e3000` | base | no_current_materialization | no_completed_job | no | - | - | 0 |
| `0x4df6b73328b639073db150c4584196c4d97053b7` | base | ready_fresh_with_topics | already_current | no | unst=1 | self=1 | 1 |
| `0x566bfa809b88967c994d77ed924bebffe80bd00c` | base | ready_fresh_with_topics | already_current | no | unst=1 | self=1 | 1 |
| `0x657e8c867d8b37dcc18fa4caead9c45eb088c642` | base | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0x6889e57bca038c28520c0b047a75e567502ea5f6` | base | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0x6c240dda6b5c336df09a4d011139beaaa1ea2aa2` | base | no_current_materialization | job_plan_artifact_absent | no | - | - | 0 |
| `0x7b6a67f1031c1d8c7bab1cf001bdaf83271241fb` | base | no_current_materialization | promotable | yes | - | - | 0 |
| `0x86b5780b606940eb59a062aa85a07959518c0161` | base | no_current_materialization | promotable | yes | - | self=1 hint=5 | 1 |
| `0x95fe19b324be69250138fe8ee50356e9f6d17cfe` | base | no_current_materialization | no_completed_job | no | - | - | 0 |
| `0xb149ef0f2539f1d9e1c9fd98d86e9c13a2aec17a` | base | ready_fresh_with_topics | already_current | no | unst=5 | self=1 hint=2 acti=2 | 1 |
| `0xb623faf559b414a1c7ef2d15f3260ca0fd239431` | base | no_current_materialization | promotable | yes | - | self=1 hint=2 | 1 |
| `0xcf5d8bc4ac508a26b038d91e8caca318a177b6c1` | base | no_current_materialization | promotable | yes | - | - | 0 |
| `0xde8a2c33655aca88f258988ed74d1511876343d1` | base | no_current_materialization | promotable | yes | - | - | 0 |
| `0xe2acf9f80a2756e51d1e53f9f41583c84279fb1f` | base | no_current_materialization | promotable | yes | - | self=1 hint=2 acti=10 | 1 |
| `0xeb927ef101080eb9b74c410cba50a7c71b7404a3` | base | no_current_materialization | promotable | yes | - | self=1 acti=2 | 1 |
| `0xf3086883ec44e1393ad4d4acb32c48ae849ef376` | base | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0x023af0d424754de795e61c17a521eeb04676c7fb` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0x02904af5c3be78481528e0f01780439f024109a6` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0x04b8136820598a4e50bee21b8b6a23fe25df9bd8` | ethereum | ready_fresh_with_topics | already_current | no | unst=12 | self=1 hint=11 | 1 |
| `0x04c0599ae5a44757c0af6f9ec3b93da8976c150a` | ethereum | config_supplied_by_caller | no_completed_job | no | - | - | 0 |
| `0x055a8b2b65d0ab4e0c17a0168d032464b7e97bdf` | ethereum | contract_not_analyzed | no_completed_job | no | - | - | 0 |
| `0x0565c8ea133ff27ba9d471330a52068a268a2b9e` | ethereum | ready_fresh_with_topics | already_current | no | unst=10 | self=1 hint=9 | 1 |
| `0x05a1552c5e18f5a0bb9571b5f2d6a4765ebda32b` | ethereum | ready_fresh_with_topics | already_current | no | unst=12 | self=1 hint=11 | 1 |
| `0x08c6f91e2b681faf5e17227f2a44c307b3c1364c` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0x0ef8fa4760db8f5cd4d993f3e3416f30f942d705` | ethereum | no_current_materialization | job_plan_artifact_absent | no | - | - | 0 |
| `0x126af21dc55c300b7d0bbfc4f3898f558ae8156b` | ethereum | ready_fresh_with_topics | already_current | no | unst=12 | self=1 hint=11 | 1 |
| `0x17a16747d03006c9754548ac0d0aff48783a4a45` | ethereum | ready_fresh_with_topics | already_current | no | unst=6 | self=1 hint=5 | 1 |
| `0x183fe88858aab892cc796662200374e3df6927e3` | ethereum | contract_not_analyzed | no_completed_job | no | - | - | 0 |
| `0x1b7a4c3797236a1c37f8741c0be35c2c72736fff` | ethereum | no_current_materialization | job_plan_artifact_absent | no | - | - | 0 |
| `0x1cb489ef513e1cc35c4657c91853a2e6ff1957de` | ethereum | no_current_materialization | promotable | yes | - | hint=2 | 0 |
| `0x1d4f0f05e50312d3e7b65659ef7d06aa74651e0c` | ethereum | no_current_materialization | promotable | yes | - | self=1 hint=11 | 1 |
| `0x1e02c841ae94d552025f6da0bb65642c409921d1` | ethereum | no_current_materialization | promotable | yes | - | self=1 acti=2 | 1 |
| `0x200057a0a4a97149b0924c5dbba868f283d903a2` | ethereum | no_current_materialization | job_plan_artifact_absent | no | - | - | 0 |
| `0x2474d68d6e9f7be77c9a343ce21dbe16f0743bd3` | ethereum | no_current_materialization | promotable | yes | - | self=1 acti=1 | 1 |
| `0x25e8162d09239fb5be50e5df18adc1ed35533e61` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0x263a74e56eb07c2a2a84fd510615a17b66e10e70` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0x28a6e7ebb6aca8f64145952a9565245c3dc1f32f` | ethereum | ready_fresh_proven_empty | already_current | no | - | - | 0 |
| `0x2aca71020de61bb532008049e1bd41e451ae8adc` | ethereum | contract_not_analyzed | no_completed_job | no | - | - | 0 |
| `0x2b90103cdc9bba6c0dbcaaf961f0b5b1920f19e3` | ethereum | no_current_materialization | job_plan_artifact_absent | no | - | - | 0 |
| `0x308861a430be4cce5502d0a12724771fc6daf216` | ethereum | no_current_materialization | job_plan_artifact_absent | no | - | - | 0 |
| `0x3311c72a04d2779f4425c036dbc40d14fec0162b` | ethereum | ready_fresh_with_topics | already_current | no | unst=1 | self=1 | 1 |
| `0x352180974c71f84a934953cf49c4e538a6f9c997` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0x35e7d6fef6f72add3c3e39dec6d9ccc29e3345fa` | ethereum | no_current_materialization | job_plan_artifact_absent | no | - | - | 0 |
| `0x35fa164735182de50811e8e2e824cfb9b6118ac2` | ethereum | no_current_materialization | job_plan_artifact_absent | no | - | - | 0 |
| `0x382d0106f308864d5462332d9d3bb54a60384b70` | ethereum | no_current_materialization | promotable | yes | - | self=1 hint=2 | 1 |
| `0x3994741a5b29c60d0ab318de1024f9256fe959dc` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0x3b44a093b9736af765f98f3245998f63bc757970` | ethereum | ready_fresh_with_topics | already_current | no | unst=1 | self=1 | 1 |
| `0x3c55986cfee455e2533f4d29006634ecf9b7c03f` | ethereum | no_current_materialization | promotable | yes | - | - | 0 |
| `0x3d320286e014c3e1ce99af6d6b00f0c1d63e3000` | ethereum | no_current_materialization | job_plan_artifact_absent | no | - | - | 0 |
| `0x3e6d22a67b9728a0866d69efa16c2e20e60a8451` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0x402dff43b4f24b006bbd6520a11c169f81085039` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0x41617d01362770ebaac10311ab899fbc8a4e4a7e` | ethereum | no_current_materialization | promotable | yes | - | self=1 hint=3 acti=1 | 1 |
| `0x417e1ef6eb82c3e6a60c2dc342e574e4c51b4d35` | ethereum | no_current_materialization | promotable | yes | - | self=1 hint=2 acti=10 | 1 |
| `0x41dfc53b13932a2690c9790527c1967d8579a6ae` | ethereum | contract_not_analyzed | no_completed_job | no | - | - | 0 |
| `0x427989bb12f4a390d11e7647d467dea02b9d2ee3` | ethereum | contract_not_analyzed | no_completed_job | no | - | - | 0 |
| `0x45d85c0a1168726bbee2352d78e7647f70654d56` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0x485bde66bb668a51f2372e34e45b1c6226798122` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0x49f954c67ff235034b69b8a59fbe309a40256c8d` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0x4a84ba0b5e716b37c78d0f5094757205626c7c1e` | ethereum | no_current_materialization | job_plan_artifact_absent | no | - | - | 0 |
| `0x4c65e8d34ecd7404fc860c4b83b081df1538bc9e` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0x4de413a26fc24c3fc27cc983be70aa9c5c299387` | ethereum | ready_fresh_with_topics | already_current | no | unst=20 | self=1 acti=19 | 1 |
| `0x4df6b73328b639073db150c4584196c4d97053b7` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0x4f81c27e750a453d6206c2d10548d6566f60886c` | ethereum | no_current_materialization | promotable | yes | - | self=1 hint=2 | 1 |
| `0x51357a700b309637f109a897a6479a563d5afb8e` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0x523455838764e0ecf9add7eab8c1dab86b0c6d7b` | ethereum | contract_not_analyzed | no_completed_job | no | - | - | 0 |
| `0x556db8c611fe63e694413f718d795f976dcf5881` | ethereum | no_current_materialization | promotable | yes | - | - | 0 |
| `0x5585996e7cfe95f2d99e61168b8b35c66ff99b18` | ethereum | no_current_materialization | job_plan_artifact_absent | no | - | - | 0 |
| `0x560441fa211aed16dd49f70c226380c9d4875225` | ethereum | contract_not_analyzed | no_completed_job | no | - | - | 0 |
| `0x57aaf0004c716388b21795431cd7d5f9d3bb6a41` | ethereum | no_current_materialization | job_plan_artifact_absent | no | - | - | 0 |
| `0x5979f753b417c17fcd8f8c87b86154a0eb0e2c17` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0x5a765826700cf3a918eb713b3a7978e9333085df` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0x5b083dde26fba0e43940b2e161fcd129903fc27d` | ethereum | no_current_materialization | promotable | yes | - | self=1 acti=4 | 1 |
| `0x5d310451276d28a90cc6910449052d29a41e3abd` | ethereum | ready_fresh_with_topics | already_current | no | unst=7 | self=1 acti=6 | 1 |
| `0x5d53b303d62a7861f88650045b8d5deb59dfb3dc` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0x5e226b1de8b0f387d7c77f78cba2571d2a1be511` | ethereum | no_current_materialization | promotable | yes | - | - | 0 |
| `0x5ec5e6b4eb6827914ca8bc3ae02c39417242adde` | ethereum | contract_not_analyzed | no_completed_job | no | - | - | 0 |
| `0x5f2ecb56ed33c86219840a2f89316285a1d9ee0f` | ethereum | no_current_materialization | promotable | yes | - | self=1 hint=2 | 1 |
| `0x5f46d540b6ed704c3c8789105f30e075aa900726` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0x603064caaf2e76c414c5f7b6667d118322d311e6` | ethereum | no_current_materialization | promotable | yes | - | self=1 hint=2 | 1 |
| `0x607d0c7e3578802eb46d388cb86cfba8ff657306` | ethereum | contract_not_analyzed | no_completed_job | no | - | - | 0 |
| `0x62247d29b4b9becf4bb73e0c722cf6445cfc7ce9` | ethereum | no_current_materialization | job_plan_artifact_absent | no | - | - | 0 |
| `0x62b283d4fefb2a120e1120dba9f83be6ca41bcd7` | ethereum | no_current_materialization | promotable | yes | - | self=1 hint=2 | 1 |
| `0x63ede83cbb1c8d90ba52e9497e6c1226a673e884` | ethereum | no_current_materialization | promotable | yes | - | self=1 hint=2 acti=9 | 1 |
| `0x6494c198a3caf90eb0a023f1191e6edc13a41042` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0x65716abb00ec074c3c1991a213b41cdc54e8212b` | ethereum | contract_not_analyzed | no_completed_job | no | - | - | 0 |
| `0x657e8c867d8b37dcc18fa4caead9c45eb088c642` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0x66aae0ee1f68c658401c7d8d6e417202a99545d7` | ethereum | no_current_materialization | promotable | yes | - | self=1 hint=2 | 1 |
| `0x66e1c53e846ef3e9f3722591868afcffb7f39800` | ethereum | no_current_materialization | promotable | yes | - | acti=5 | 0 |
| `0x6889e57bca038c28520c0b047a75e567502ea5f6` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0x68ec1fdd4bb202b2e07ae751cb5553644aa48cfa` | ethereum | contract_not_analyzed | no_completed_job | no | - | - | 0 |
| `0x6bf6acd4b22795080c719d987baa8f4fcb1ab3f8` | ethereum | no_current_materialization | promotable | yes | - | self=1 hint=1 | 1 |
| `0x6c7c54cfc2225fa985cd25f04d923b93c60a02f8` | ethereum | no_current_materialization | promotable | yes | - | - | 0 |
| `0x6db24ee656843e3fe03eb8762a54d86186ba6b64` | ethereum | no_current_materialization | job_plan_artifact_absent | no | - | - | 0 |
| `0x70a64840a353c58f63333570f53dba0948bece3d` | ethereum | no_current_materialization | promotable | yes | - | - | 0 |
| `0x71e2d6c34f569cc4df5802d675b208fb8ae3bcd6` | ethereum | contract_not_analyzed | no_completed_job | no | - | - | 0 |
| `0x7223442cad8e9ca474fc40109ab981608f8c4273` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0x747cac75776b3a0bba3de3e61ec12a6a7f52232e` | ethereum | no_current_materialization | promotable | yes | - | - | 0 |
| `0x7623e9dc0da6ff821ddb9ebaba794054e078f8c4` | ethereum | no_current_materialization | promotable | yes | - | hint=2 acti=2 | 0 |
| `0x77b929befe793367712c0c28ca8e857bf23a2296` | ethereum | no_current_materialization | promotable | yes | - | self=1 hint=3 acti=1 | 1 |
| `0x7837cd2f99f2e3c192e4492f580f2790a30e34f9` | ethereum | no_current_materialization | promotable | yes | - | self=1 hint=3 acti=3 | 1 |
| `0x7859baa3e12b6480b15b77b069d8d0279ebc74ea` | ethereum | contract_not_analyzed | no_completed_job | no | - | - | 0 |
| `0x78c61b1ea2507c4c2b13f77951549d4e76acb52b` | ethereum | no_current_materialization | promotable | yes | - | self=1 hint=3 acti=3 | 1 |
| `0x7a00657a45420044bc526b90ad667affaee0a868` | ethereum | contract_not_analyzed | no_completed_job | no | - | - | 0 |
| `0x7b5ae07e2af1c861bcc4736d23f5f66a61e0ca5e` | ethereum | no_current_materialization | job_plan_artifact_absent | no | - | - | 0 |
| `0x7c12c550fe8857380b8f5a9e55d9145a0d7a7198` | ethereum | no_current_materialization | promotable | yes | - | self=1 hint=2 acti=2 | 1 |
| `0x7c5c721ff970d86cede81cbb81914dd7c2dcb234` | ethereum | no_current_materialization | promotable | yes | - | self=1 acti=2 | 1 |
| `0x7d5706f6ef3f89b3951e23e557cdfbc3239d4e2c` | ethereum | no_current_materialization | job_plan_artifact_absent | no | - | - | 0 |
| `0x7dcbd5c38c128f83aa8264120bcec8662f35adaf` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0x7ec91c297a3b35ae9caa63a3fc638f24202071d4` | ethereum | no_current_materialization | promotable | yes | - | self=1 acti=2 | 1 |
| `0x80ce8a917beec6db0f632f2710916fcaa621874a` | ethereum | contract_not_analyzed | already_current | no | - | - | 0 |
| `0x829675330fdcee01022983493e71f73fb53eab45` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0x83599937c2c9bea0e0e8ac096c6f32e86486b410` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0x851dd540f4d2ec78120de0a0cc87b21ede5df5c6` | ethereum | contract_not_analyzed | no_completed_job | no | - | - | 0 |
| `0x86b5780b606940eb59a062aa85a07959518c0161` | ethereum | ready_fresh_with_topics | already_current | no | unst=6 | self=1 hint=5 | 1 |
| `0x89e45081437c959a827d2027135bc201ab33a2c8` | ethereum | no_current_materialization | job_plan_artifact_absent | no | - | - | 0 |
| `0x8b71140ad2e5d1e7018d2a7f8a288bd3cd38916f` | ethereum | no_current_materialization | promotable | yes | - | - | 0 |
| `0x8f08b70456eb22f6109f57b8fafe862ed28e6040` | ethereum | no_current_materialization | job_plan_artifact_absent | no | - | - | 0 |
| `0x917cee801a67f933f2e6b33fc0cd1ed2d5909d88` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0x91a2482ea778f3c9aae1d3768d9e558d6794b972` | ethereum | no_current_materialization | promotable | yes | - | self=1 hint=2 | 1 |
| `0x929b44db23740e65df3a81ea4aab716af1b88474` | ethereum | no_current_materialization | promotable | yes | - | self=1 hint=2 acti=10 | 1 |
| `0x93fff4028927f53f708534397ed349b9cd4e2f9f` | ethereum | no_current_materialization | promotable | yes | - | - | 0 |
| `0x95fe19b324be69250138fe8ee50356e9f6d17cfe` | ethereum | ready_fresh_with_topics | already_current | no | unst=12 | self=1 hint=11 | 1 |
| `0x989468982b08aefa46e37cd0086142a86fa466d7` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0x99de9e5a3ec2750a6983c8732e6e795a35e7b861` | ethereum | no_current_materialization | promotable | yes | - | self=1 hint=2 acti=10 | 1 |
| `0x9ea4d0fd09b628e23b1998f2153e27e5261b1b67` | ethereum | ready_fresh_with_topics | already_current | no | unst=2 | self=1 acti=1 | 1 |
| `0x9f26d4c958fd811a1f59b01b86be7dffc9d20761` | ethereum | ready_fresh_with_topics | already_current | no | unst=1 | acti=1 | 0 |
| `0x9ffdf407cde9a93c47611799da23924af3ef764f` | ethereum | no_current_materialization | job_plan_artifact_absent | no | - | - | 0 |
| `0x9ffeef56dfb45a44c51543f3a08d0c91948e9f56` | ethereum | no_current_materialization | promotable | yes | - | self=1 acti=2 | 1 |
| `0xa000244b4a36d57ea1ecb39b5f02f255e4c8cd52` | ethereum | contract_not_analyzed | no_completed_job | no | - | - | 0 |
| `0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48` | ethereum | config_supplied_by_caller | job_plan_artifact_absent | no | - | - | 0 |
| `0xa24dd7b978fbe36125cc4817192f7b8aa18d213c` | ethereum | no_current_materialization | promotable | yes | - | self=1 hint=2 | 1 |
| `0xa55a34d31af7e1bddface2966d51526eccf4f76e` | ethereum | no_current_materialization | promotable | yes | - | self=1 hint=2 acti=10 | 1 |
| `0xa6ca0607190d03cf16fe6f2865cf40c3d160ccf3` | ethereum | no_current_materialization | promotable | yes | - | self=1 hint=1 | 1 |
| `0xa9dbe5c7c8172ef83a30c143892e0010420e6307` | ethereum | no_current_materialization | promotable | yes | - | - | 0 |
| `0xaba6ba1e95e0926a6a6b917fe4e2f19ceae4ff2e` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0xabbc3e6bccd53c55fee9a785f30a3a8202e6f61e` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0xaf66ad820d96ae3dd6dd6ff2296592b7ac0b975f` | ethereum | no_current_materialization | promotable | yes | - | self=1 hint=3 acti=3 | 1 |
| `0xafa8c08bedb2ec1bbeb64a7ffa44c604e7cca68d` | ethereum | no_current_materialization | promotable | yes | - | self=1 hint=2 | 1 |
| `0xafb82ce44fd8a3431a64742bcd3547eeda1afea7` | ethereum | ready_fresh_with_topics | already_current | no | unst=1 | self=1 | 1 |
| `0xb12fff6512712ea3b30eeab6f9dea2fe903ca6ab` | ethereum | no_current_materialization | promotable | yes | - | self=1 hint=2 | 1 |
| `0xb35a429474404e2eda28548075623993a40239b6` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0xb49e4420ea6e35f98060cd133842dbea9c27e479` | ethereum | no_current_materialization | promotable | yes | - | - | 0 |
| `0xb53244f7716dc83811c8fb1a91971dc188c1c5aa` | ethereum | ready_fresh_with_topics | already_current | no | unst=12 | self=1 hint=11 | 1 |
| `0xb7e852e169f8104396fff7c25430299bbdac91b1` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0xba538b15bbca0cb5e3ad844241c7a0d2dfc4f13b` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0xbae19b38bf727be64af0b578c34985c3d612e2ba` | ethereum | no_current_materialization | promotable | yes | - | self=1 hint=11 | 1 |
| `0xbc0f3b23930fff9f4894914bd745ababa9588265` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0xbc870c47c6eb10009a0720e76f166f104c124ecf` | ethereum | ready_fresh_with_topics | already_current | no | unst=1 | self=1 | 1 |
| `0xbe16605b22a7facef247363312121670dfe5afbe` | ethereum | no_current_materialization | promotable | yes | - | self=1 hint=11 | 1 |
| `0xbe386b1fb51ffacae0522a5da099371cd4a2aaea` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0xc315d6e14ddcdc7407784e2caf815d131bc1d3e7` | ethereum | ready_fresh_with_topics | already_current | no | unst=10 | self=1 hint=9 | 1 |
| `0xc673ef7791724f0dcca38adb47fbb3aef3db6c80` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0xc8c58d1567e1db8c02542e6df5241a0d71f91fe2` | ethereum | no_current_materialization | promotable | yes | - | self=1 hint=2 acti=9 | 1 |
| `0xc9ca4f230d30913877c9a18eef7e907ee32ebef2` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0xca8711daf13d852ed2121e4be3894dae366039e4` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0xcd425f44758a08baab3c4908f3e3de5776e45d7a` | ethereum | no_current_materialization | promotable | yes | - | acti=1 | 0 |
| `0xcd5fe23c85820f7b72d0926fc9b05b43e359b7ee` | ethereum | no_current_materialization | job_plan_artifact_absent | no | - | - | 0 |
| `0xcdd57d11476c22d265722f68390b036f3da48c21` | ethereum | contract_not_analyzed | no_completed_job | no | - | - | 0 |
| `0xcea8039076e35a825854c5c2f85659430b06ec96` | ethereum | contract_not_analyzed | no_completed_job | no | - | - | 0 |
| `0xcf5928ea7d7f164ec868ceda7a69e08a102b5e05` | ethereum | no_current_materialization | promotable | yes | - | acti=3 | 0 |
| `0xd022d6bb8b6c1c357ec77d930dc6a0ad40ffc90b` | ethereum | contract_not_analyzed | no_completed_job | no | - | - | 0 |
| `0xd1901dd36cbf4a81386d0162df2707f7ddb60527` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0xd2b8c78a5eb18a5f3b0392c5479bb45c77d02ff5` | ethereum | no_current_materialization | promotable | yes | - | self=4 acti=4 | 4 |
| `0xd43d99df3d42675ce126a7cff8f7dff037620851` | ethereum | no_current_materialization | promotable | yes | - | self=1 acti=1 | 1 |
| `0xd5edf7730abad812247f6f54d7bd31a52554e35e` | ethereum | no_current_materialization | job_plan_artifact_absent | no | - | - | 0 |
| `0xd789870bea40d056a4d26055d0befcc8755da146` | ethereum | no_current_materialization | job_plan_artifact_absent | no | - | - | 0 |
| `0xdadef1ffbfeaab4f68a9fd181395f68b4e4e7ae0` | ethereum | no_current_materialization | job_plan_artifact_absent | no | - | - | 0 |
| `0xe2acf9f80a2756e51d1e53f9f41583c84279fb1f` | ethereum | no_current_materialization | job_schema_version_not_current | no | - | - | 0 |
| `0xeb927ef101080eb9b74c410cba50a7c71b7404a3` | ethereum | no_current_materialization | promotable | yes | - | self=1 acti=2 | 1 |
| `0xed87ae68bb0db3ec922004f8dace44a7c5390894` | ethereum | contract_not_analyzed | no_completed_job | no | - | - | 0 |
| `0xeda663610638e6557c27e2f4e973d3393e844e70` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0xf0bb20865277abd641a307ece5ee04e79073416c` | ethereum | no_current_materialization | promotable | yes | - | self=1 | 1 |
| `0xf155a2632ef263a6a382028b3b33feb29175b8a5` | ethereum | contract_not_analyzed | no_completed_job | no | - | - | 0 |
| `0xf44bd12956a0a87c2c20113ddfe1537a442526b5` | ethereum | ready_fresh_with_topics | already_current | no | unst=12 | self=1 hint=11 | 1 |
| `0xf46d3734564ef9a5a16fc3b1216831a28f78e2b5` | ethereum | contract_not_analyzed | no_completed_job | no | - | - | 0 |
| `0xfbfe6b9cee0e555bad7e2e7309effc75200cbe38` | ethereum | no_current_materialization | job_plan_artifact_absent | no | - | - | 0 |
| `0xfe0c30065b384f05761f15d0cc899d4f9f9cc0eb` | ethereum | no_current_materialization | promotable | yes | - | acti=3 | 0 |

## Watches gaining notify rights, with their qualification witness

Only `self_describing` occurrences reach the notifier. Each row below is a
spec that would publish and notify after the sweep and did not before, with
the arm of `classify_witness_tier` that earns it.

| address | event | controller | witness kind | witness |
|---|---|---|---|---|
| `0x05a1552c5e18f5a0bb9571b5f2d6a4765ebda32b` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x1509b1fdd01caf9697aff514b9574b4a27173dd2` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x1f21ada3c59b81d7b1bcf5f80f4acfd31ba356e3` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x382d0106f308864d5462332d9d3bb54a60384b70` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x4df6b73328b639073db150c4584196c4d97053b7` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x566bfa809b88967c994d77ed924bebffe80bd00c` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x657e8c867d8b37dcc18fa4caead9c45eb088c642` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x6889e57bca038c28520c0b047a75e567502ea5f6` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x86b5780b606940eb59a062aa85a07959518c0161` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0xb149ef0f2539f1d9e1c9fd98d86e9c13a2aec17a` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0xb623faf559b414a1c7ef2d15f3260ca0fd239431` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0xe2acf9f80a2756e51d1e53f9f41583c84279fb1f` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0xeb927ef101080eb9b74c410cba50a7c71b7404a3` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0xf3086883ec44e1393ad4d4acb32c48ae849ef376` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x023af0d424754de795e61c17a521eeb04676c7fb` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x02904af5c3be78481528e0f01780439f024109a6` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x04b8136820598a4e50bee21b8b6a23fe25df9bd8` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x0565c8ea133ff27ba9d471330a52068a268a2b9e` | Initialized(uint8) (initialized) | state_variable:BEACON_GENESIS_TIME | canonical_family | `{"family": "initialized", "signature": "Initialized(uint8)"}` |
| `0x05a1552c5e18f5a0bb9571b5f2d6a4765ebda32b` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x08c6f91e2b681faf5e17227f2a44c307b3c1364c` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x126af21dc55c300b7d0bbfc4f3898f558ae8156b` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x17a16747d03006c9754548ac0d0aff48783a4a45` | Initialized(uint8) (initialized) | state_variable:_initialized | canonical_family | `{"family": "initialized", "signature": "Initialized(uint8)"}` |
| `0x1d4f0f05e50312d3e7b65659ef7d06aa74651e0c` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x1e02c841ae94d552025f6da0bb65642c409921d1` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x2474d68d6e9f7be77c9a343ce21dbe16f0743bd3` | Initialized(uint8) (initialized) | state_variable:_initialized | canonical_family | `{"family": "initialized", "signature": "Initialized(uint8)"}` |
| `0x25e8162d09239fb5be50e5df18adc1ed35533e61` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x263a74e56eb07c2a2a84fd510615a17b66e10e70` | Initialized(uint8) (initialized) | state_variable:_initialized | canonical_family | `{"family": "initialized", "signature": "Initialized(uint8)"}` |
| `0x3311c72a04d2779f4425c036dbc40d14fec0162b` | Initialized(uint8) (initialized) | state_variable:_initialized | canonical_family | `{"family": "initialized", "signature": "Initialized(uint8)"}` |
| `0x352180974c71f84a934953cf49c4e538a6f9c997` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x382d0106f308864d5462332d9d3bb54a60384b70` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x3994741a5b29c60d0ab318de1024f9256fe959dc` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x3b44a093b9736af765f98f3245998f63bc757970` | Initialized(uint8) (initialized) | state_variable:_initialized | canonical_family | `{"family": "initialized", "signature": "Initialized(uint8)"}` |
| `0x3e6d22a67b9728a0866d69efa16c2e20e60a8451` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x402dff43b4f24b006bbd6520a11c169f81085039` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x41617d01362770ebaac10311ab899fbc8a4e4a7e` | Initialized(uint8) (initialized) | state_variable:_initialized | canonical_family | `{"family": "initialized", "signature": "Initialized(uint8)"}` |
| `0x417e1ef6eb82c3e6a60c2dc342e574e4c51b4d35` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x45d85c0a1168726bbee2352d78e7647f70654d56` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x485bde66bb668a51f2372e34e45b1c6226798122` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x49f954c67ff235034b69b8a59fbe309a40256c8d` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x4c65e8d34ecd7404fc860c4b83b081df1538bc9e` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x4de413a26fc24c3fc27cc983be70aa9c5c299387` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x4df6b73328b639073db150c4584196c4d97053b7` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x4f81c27e750a453d6206c2d10548d6566f60886c` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x51357a700b309637f109a897a6479a563d5afb8e` | Initialized(uint8) (initialized) | state_variable:_initialized | canonical_family | `{"family": "initialized", "signature": "Initialized(uint8)"}` |
| `0x5979f753b417c17fcd8f8c87b86154a0eb0e2c17` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x5a765826700cf3a918eb713b3a7978e9333085df` | Initialized(uint8) (initialized) | state_variable:_initialized | canonical_family | `{"family": "initialized", "signature": "Initialized(uint8)"}` |
| `0x5b083dde26fba0e43940b2e161fcd129903fc27d` | Initialized(uint8) (initialized) | state_variable:_initialized | canonical_family | `{"family": "initialized", "signature": "Initialized(uint8)"}` |
| `0x5d310451276d28a90cc6910449052d29a41e3abd` | Initialized(uint64) (initialized) | external_contract:_eEth | canonical_family | `{"family": "initialized", "signature": "Initialized(uint64)"}` |
| `0x5d53b303d62a7861f88650045b8d5deb59dfb3dc` | Initialized(uint8) (initialized) | state_variable:_initialized | canonical_family | `{"family": "initialized", "signature": "Initialized(uint8)"}` |
| `0x5f2ecb56ed33c86219840a2f89316285a1d9ee0f` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x5f46d540b6ed704c3c8789105f30e075aa900726` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x603064caaf2e76c414c5f7b6667d118322d311e6` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x62b283d4fefb2a120e1120dba9f83be6ca41bcd7` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x63ede83cbb1c8d90ba52e9497e6c1226a673e884` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x6494c198a3caf90eb0a023f1191e6edc13a41042` | Initialized(uint8) (initialized) | state_variable:_initialized | canonical_family | `{"family": "initialized", "signature": "Initialized(uint8)"}` |
| `0x657e8c867d8b37dcc18fa4caead9c45eb088c642` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x66aae0ee1f68c658401c7d8d6e417202a99545d7` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x6889e57bca038c28520c0b047a75e567502ea5f6` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x6bf6acd4b22795080c719d987baa8f4fcb1ab3f8` | Initialized(uint8) (initialized) | state_variable:_initialized | canonical_family | `{"family": "initialized", "signature": "Initialized(uint8)"}` |
| `0x7223442cad8e9ca474fc40109ab981608f8c4273` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x77b929befe793367712c0c28ca8e857bf23a2296` | Initialized(uint8) (initialized) | state_variable:_initialized | canonical_family | `{"family": "initialized", "signature": "Initialized(uint8)"}` |
| `0x7837cd2f99f2e3c192e4492f580f2790a30e34f9` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x78c61b1ea2507c4c2b13f77951549d4e76acb52b` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x7c12c550fe8857380b8f5a9e55d9145a0d7a7198` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x7c5c721ff970d86cede81cbb81914dd7c2dcb234` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x7dcbd5c38c128f83aa8264120bcec8662f35adaf` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x7ec91c297a3b35ae9caa63a3fc638f24202071d4` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x829675330fdcee01022983493e71f73fb53eab45` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x83599937c2c9bea0e0e8ac096c6f32e86486b410` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x86b5780b606940eb59a062aa85a07959518c0161` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x917cee801a67f933f2e6b33fc0cd1ed2d5909d88` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x91a2482ea778f3c9aae1d3768d9e558d6794b972` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x929b44db23740e65df3a81ea4aab716af1b88474` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x95fe19b324be69250138fe8ee50356e9f6d17cfe` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x989468982b08aefa46e37cd0086142a86fa466d7` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x99de9e5a3ec2750a6983c8732e6e795a35e7b861` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0x9ea4d0fd09b628e23b1998f2153e27e5261b1b67` | Initialized(uint8) (initialized) | state_variable:_initialized | canonical_family | `{"family": "initialized", "signature": "Initialized(uint8)"}` |
| `0x9ffeef56dfb45a44c51543f3a08d0c91948e9f56` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0xa24dd7b978fbe36125cc4817192f7b8aa18d213c` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0xa55a34d31af7e1bddface2966d51526eccf4f76e` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0xa6ca0607190d03cf16fe6f2865cf40c3d160ccf3` | Initialized(uint8) (initialized) | state_variable:_initialized | canonical_family | `{"family": "initialized", "signature": "Initialized(uint8)"}` |
| `0xaba6ba1e95e0926a6a6b917fe4e2f19ceae4ff2e` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0xabbc3e6bccd53c55fee9a785f30a3a8202e6f61e` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0xaf66ad820d96ae3dd6dd6ff2296592b7ac0b975f` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0xafa8c08bedb2ec1bbeb64a7ffa44c604e7cca68d` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0xafb82ce44fd8a3431a64742bcd3547eeda1afea7` | Initialized(uint8) (initialized) | state_variable:_initialized | canonical_family | `{"family": "initialized", "signature": "Initialized(uint8)"}` |
| `0xb12fff6512712ea3b30eeab6f9dea2fe903ca6ab` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0xb35a429474404e2eda28548075623993a40239b6` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0xb53244f7716dc83811c8fb1a91971dc188c1c5aa` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0xb7e852e169f8104396fff7c25430299bbdac91b1` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0xba538b15bbca0cb5e3ad844241c7a0d2dfc4f13b` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0xbae19b38bf727be64af0b578c34985c3d612e2ba` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0xbc0f3b23930fff9f4894914bd745ababa9588265` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0xbc870c47c6eb10009a0720e76f166f104c124ecf` | Initialized(uint8) (initialized) | state_variable:_initialized | canonical_family | `{"family": "initialized", "signature": "Initialized(uint8)"}` |
| `0xbe16605b22a7facef247363312121670dfe5afbe` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0xbe386b1fb51ffacae0522a5da099371cd4a2aaea` | Initialized(uint8) (initialized) | state_variable:_initialized | canonical_family | `{"family": "initialized", "signature": "Initialized(uint8)"}` |
| `0xc315d6e14ddcdc7407784e2caf815d131bc1d3e7` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0xc673ef7791724f0dcca38adb47fbb3aef3db6c80` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0xc8c58d1567e1db8c02542e6df5241a0d71f91fe2` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0xc9ca4f230d30913877c9a18eef7e907ee32ebef2` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0xca8711daf13d852ed2121e4be3894dae366039e4` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0xd1901dd36cbf4a81386d0162df2707f7ddb60527` | Initialized(uint8) (initialized) | state_variable:_initialized | canonical_family | `{"family": "initialized", "signature": "Initialized(uint8)"}` |
| `0xd2b8c78a5eb18a5f3b0392c5479bb45c77d02ff5` | TokenMaxPositionWeightLimitUpdated(uint64,uint64) (state_changed:state_variable:_tokenInfos) | state_variable:_tokenInfos | old_new_args_single_writer | `{"args": ["oldLimit", "newLimit"], "writes": ["_tokenInfos"]}` |
| `0xd2b8c78a5eb18a5f3b0392c5479bb45c77d02ff5` | PriceProviderSet(address,address) (state_changed:external_contract:priceProvider) | external_contract:priceProvider | old_new_args_single_writer | `{"args": ["oldPriceProvider", "newPriceProvider"], "writes": ["priceProvider"]}` |
| `0xd2b8c78a5eb18a5f3b0392c5479bb45c77d02ff5` | RebalancerSet(address,address) (controller_changed:state_variable:rebalancer) | state_variable:rebalancer | old_new_args_single_writer | `{"args": ["oldRebalancer", "newRebalancer"], "writes": ["rebalancer"]}` |
| `0xd2b8c78a5eb18a5f3b0392c5479bb45c77d02ff5` | SwapperSet(address,address) (state_changed:external_contract:swapper) | external_contract:swapper | old_new_args_single_writer | `{"args": ["oldSwapper", "newSwapper"], "writes": ["swapper"]}` |
| `0xd43d99df3d42675ce126a7cff8f7dff037620851` | Initialized(uint8) (initialized) | state_variable:_initialized | canonical_family | `{"family": "initialized", "signature": "Initialized(uint8)"}` |
| `0xeb927ef101080eb9b74c410cba50a7c71b7404a3` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0xeda663610638e6557c27e2f4e973d3393e844e70` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0xf0bb20865277abd641a307ece5ee04e79073416c` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
| `0xf44bd12956a0a87c2c20113ddfe1537a442526b5` | AuthorityUpdated(address,address) (authority_updated) | external_contract:authority | canonical_family | `{"family": "authority_updated", "signature": "AuthorityUpdated(address,address)"}` |
