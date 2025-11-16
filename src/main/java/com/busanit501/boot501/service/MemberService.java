package com.busanit501.boot501.service;

import com.busanit501.boot501.domain.Member;
import com.busanit501.boot501.dto.MemberJoinDTO;
import com.busanit501.boot501.dto.upload.UploadResultDTO;
import org.springframework.web.multipart.MultipartFile;


public interface MemberService {
    // 중복 아이디 예외처리
    static class MidExistException extends Exception {

    }

    //중복 아이디 검사

    boolean checkMid(String mid);

    void join(MemberJoinDTO memberJoinDTO) throws MidExistException;

    //회원 수정 재사용. join
    void update(MemberJoinDTO memberJoinDTO) throws MidExistException;

    //소셜 로그인시 수정하는 서비스
    void updateSocial(String mid, String mpw) throws MidExistException;

    default Member dtoToEntity(MemberJoinDTO memberJoinDTO) {

        Member member = Member.builder()
                .mid(memberJoinDTO.getMid())
                .mpw(memberJoinDTO.getMpw())
                .email(memberJoinDTO.getEmail())
                .memberName(memberJoinDTO.getMemberName())
                .address(memberJoinDTO.getAddress())
                .uuid(memberJoinDTO.getUuid())
                .fileName(memberJoinDTO.getFileName())
                .build();


        return member;

    } // dtoToEntity 닫기.

    // entityToDTO
    // 화면(DTO) ->  컨트롤러 ->서비스(각 변환작업을함.) - Entity 타입으로 - DB
    default MemberJoinDTO entityToDTO(Member member) {
        MemberJoinDTO memberJoinDTO = MemberJoinDTO.builder()
                .mid(member.getMid())
                .mpw(member.getMpw())
                .email(member.getEmail())
                .uuid(member.getUuid())
                .fileName(member.getFileName())
                .build();


        return memberJoinDTO;
    }

    //프로필 이미지 업로드
    public UploadResultDTO uploadProfileImage(MultipartFile fileImageName);


}
