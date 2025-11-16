package com.busanit501.boot501.security;

import com.busanit501.boot501.domain.Member;
import com.busanit501.boot501.repository.MemberRepository;
import com.busanit501.boot501.security.dto.MemberSecurityDTO;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.stream.Collectors;

@Log4j2
@Service

public class CustomUserDetailsService implements UserDetailsService {

    // 스프링 시큐리티 설정 클래스에 빈으로 등록한 인스턴스 주입하기.
    private PasswordEncoder passwordEncoder;

    // MemberRepository 넣기.
    @Autowired
    private MemberRepository memberRepository;

    //생성자로 주입하기.
    public CustomUserDetailsService() {
        this.passwordEncoder = new BCryptPasswordEncoder();
    }

    // 로그인 로직 처리시, 여기를 반드시 거쳐 감.
    // username : 로그인한 유저이름.
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("CustomUserDetailsService loadUserByUsername 확인 : "+ username);

        //User, 스프링 시큐리티에서 제공하는 기본 클래스,
        // 사용자 가 만든 User 가 아니다. 우리는 Member 사용할 예정.

        //더미 데이터 임시 테스트
//        UserDetails userDetails = User.builder()
//                .username("lsy2")
//                .password(passwordEncoder.encode("123456"))
//                // 더미 데이터, 더미 권한.
//                .authorities("ROLE_USER")
////                .authorities("ROLE_ADMIN")
//                .build();
        // 로그인 한 유저명으로, 디비에서 검색을함.
        Optional<Member> result = memberRepository.getWithRoles(username);

        if(result.isEmpty()){
            //예외 처리.
            throw new UsernameNotFoundException("유저가 존재하지 않습니다");
        }
        // 디비에 해당 유저가 있다면, 이어서 로그인 처리하기.
        Member member = result.get();

        // entity -> dto(UserDetails 타입), MemberSecurityDTO
        // 권한 관련 커스텀 마이징 하기 어려워서 -> 기존 A a = new A();
//        MemberSecurityDTO memberSecurityDTO = MemberSecurityDTO.builder()
//                .mid(member.getMid())
//                .mpw(member.getMpw())
//                .email(member.getEmail())
//                .del(member.isDel())
//                .social(false)
//                .
//                .build();
        MemberSecurityDTO memberSecurityDTO = new MemberSecurityDTO(
           member.getMid(),
           member.getMpw(),
           member.getEmail(),
           member.isDel(),
           false,
           member.getUuid(),
           member.getFileName(),
           member.getProfileImageServer(),
           member.getRoleSet().stream().map(
                   memberRole -> new SimpleGrantedAuthority("ROLE_"+ memberRole.name())
           ).collect(Collectors.toList()),
                member.getMemberName(),
                member.getAddress()
        );
        log.info("CustomUserDetailsService loadUserByUsername memberSecurityDTO 확인 :" + memberSecurityDTO);

        return memberSecurityDTO;
    }
}
