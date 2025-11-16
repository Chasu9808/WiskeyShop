package com.busanit501.boot501.repository;

import com.busanit501.boot501.domain.Member;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {

    // 소셜 로그인이 아닌, 일반 로그인으로 검색하기.
    // N+1,한번에 다같이 조회를 하자. in 연산자 이용해서, 하나의 쿼리로 동작하기.
    @EntityGraph(attributePaths = "roleSet")
    @Query("select m from Member m where m.mid = :mid and m.social = false ")
    Optional<Member> getWithRoles(String mid);

    // 이메일으로 유저 확인.
    @EntityGraph(attributePaths = "roleSet")
    Optional<Member> findByEmail(String email);

    // mid로 유저 확인.
    @EntityGraph(attributePaths = "roleSet")
    Optional<Member> findByMid(String mid);

    //DML 적용하기
    @Modifying
    @Transactional
    @Query("update Member m set m.mpw=:mpw where m.mid = :mid")
    void updatePassword(@Param("mpw") String mpw, @Param("mid") String mid);

}
