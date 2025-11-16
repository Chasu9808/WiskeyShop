package com.busanit501.boot501.security.dto;

//시큐리티 필터 설정이 되어 있고,
// 로그인 처리를 우리가 하는게 아니라, 시큐리티가 함.
// 시큐리티는 그냥 클래스를 요구하지 않고,
// 자기들이 정해둔 룰. UserDetails 를 반환하는 클래스를 요구를 해요.
// 시큐리티에서 정의해둔 특정 클래스를 상속을 받으면 됨.

import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Map;

@Getter
@Setter
@ToString
//@AllArgsConstructor
// @AllArgsConstructor 대신에 권한도, 시큐리티에서 가져와서, 사용자정의해야하서.
public class MemberSecurityDTO extends User implements OAuth2User {
    private String mid;
    private String mpw;
    private String email;
    private String memberName;
    private String address;
    private boolean del;
    private boolean social;
    private String uuid;
    private String fileName;
    //소셜 로그인 정보
    private Map<String, Object> props;
    // 소셜 프로필 이미지 만 뽑기
    private String profileImageServer;

    //생성자
    public MemberSecurityDTO(
            //로그인한 유저이름.
            String username,String password,String email,
            boolean del, boolean social,
            String uuid, String fileName,
            String profileImageServer,
            //GrantedAuthority 를 상속한 클래스는 아무나 올수 있다. 타입으로
            Collection<? extends GrantedAuthority> authorities,
            String memberName,
            String address
    ){
      super(username, password, authorities);
      this.mid = username;
      this.mpw = password;
      this.email = email;
      this.profileImageServer = profileImageServer;
      this.del = del;
      this.social = social;
      this.uuid = uuid;
      this.fileName = fileName;
      this.memberName = memberName;
      this.address = address;
    }

    // 카카오 인증 연동시 , 필수 재정의 메서드
    @Override
    public Map<String, Object> getAttributes() {
        return this.getProps();
    }

    @Override
    public String getName() {
        return this.mid;
    }
}
