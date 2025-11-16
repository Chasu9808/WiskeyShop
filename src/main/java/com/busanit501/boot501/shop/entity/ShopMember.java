package com.busanit501.boot501.shop.entity;


//@Entity
//@Table(name="shopmember")
//@Getter @Setter
//@ToString
//public class ShopMember extends BaseEntity {
//
//    @Id
//    @Column(name="member_id")
//    @GeneratedValue(strategy = GenerationType.AUTO)
//    private Long id;
//
//    private String name;
//
//    @Column(unique = true)
//    private String email;
//
//    private String password;
//
//    private String address;
//
//    @Enumerated(EnumType.STRING)
//    private Role role;
//
//    public static ShopMember createMember(MemberFormDto memberFormDto, PasswordEncoder passwordEncoder){
//        ShopMember shopMember = new ShopMember();
//        shopMember.setName(memberFormDto.getName());
//        shopMember.setEmail(memberFormDto.getEmail());
//        shopMember.setAddress(memberFormDto.getAddress());
//        String password = passwordEncoder.encode(memberFormDto.getPassword());
//        shopMember.setPassword(password);
//        shopMember.setRole(Role.ADMIN);
//        return shopMember;
//    }
//
//}
