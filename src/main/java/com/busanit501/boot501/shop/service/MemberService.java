package com.busanit501.boot501.shop.service;


//@Service
//@Transactional
//@RequiredArgsConstructor
//public class MemberService implements UserDetailsService {
//
//    private final ShopMemberRepository memberRepository;
//
//    public ShopMember saveMember(ShopMember shopMember){
//        validateDuplicateMember(shopMember);
//        return memberRepository.save(shopMember);
//    }
//
//    private void validateDuplicateMember(ShopMember shopMember){
//        ShopMember findShopMember = memberRepository.findByEmail(shopMember.getEmail());
//        if(findShopMember != null){
//            throw new IllegalStateException("이미 가입된 회원입니다.");
//        }
//    }
//
//    @Override
//    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
//
//        ShopMember shopMember = memberRepository.findByEmail(email);
//
//        if(shopMember == null){
//            throw new UsernameNotFoundException(email);
//        }
//
//        return User.builder()
//                .username(shopMember.getEmail())
//                .password(shopMember.getPassword())
//                .roles(shopMember.getRole().toString())
//                .build();
//    }
//
//}