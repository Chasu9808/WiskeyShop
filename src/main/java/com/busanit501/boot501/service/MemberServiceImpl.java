package com.busanit501.boot501.service;

import com.busanit501.boot501.domain.Member;
import com.busanit501.boot501.domain.MemberRole;
import com.busanit501.boot501.dto.MemberJoinDTO;
import com.busanit501.boot501.dto.upload.UploadResultDTO;
import com.busanit501.boot501.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import net.coobird.thumbnailator.Thumbnailator;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;
import java.util.UUID;

@Service
@Log4j2
@RequiredArgsConstructor
public class MemberServiceImpl implements MemberService {
    @Value("${com.busanit501.upload.path}")
    private String uploadPath;

    // 다른 기능들 도움 받기, 의존, 주입, 포함 관계 ,
    private final ModelMapper modelMapper;
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;


    @Override
    public boolean checkMid(String mid) {
        Optional<Member> result = memberRepository.findByMid(mid);
        if (result.isPresent()) {
            return true;
        } else {
            return false;
        }
    }

    @Override
    public void join(MemberJoinDTO memberJoinDTO) throws MidExistException {
        //기존 아이디와 중복되는지 여부 확인
        String mid = memberJoinDTO.getMid();
        Optional<Member> result = memberRepository.findByMid(mid);

        if (result.isPresent()) {
            throw new MidExistException();
        }

        // 중복이 아니니 회원 가입 처리하기.
//         Member member = modelMapper.map(memberJoinDTO, Member.class);
        log.info("memberJoinDTO = 4 MemberServiceImpl 프로필 이미지 있는 경우  " + memberJoinDTO);
        Member member = dtoToEntity(memberJoinDTO);
        log.info("memberJoinDTO = 5 member MemberServiceImpl 프로필 이미지 있는 경우  " + member);
        //패스워드는 현재 평문 -> 암호로 변경.
        member.changePassword(passwordEncoder.encode(member.getMpw()));
        // 역할 추가. 기본 USER
        member.addRole(MemberRole.USER);


        // 데이터 가 잘 알맞게 변경이 됐는지 여부,
        log.info("joinMember: " + member);
        log.info("joinMember: " + member.getRoleSet());

        // 디비에 적용하기.
        memberRepository.save(member);

    }


    // 일반회원 정보 수정.
    @Override
    public void update(MemberJoinDTO memberJoinDTO) throws MidExistException {

        log.info("memberJoinDTO = 4 MemberServiceImpl 프로필 이미지 있는 경우  " + memberJoinDTO);
        Member member = null;
        if(memberJoinDTO.getUuid() == null) {
            // 기존 이미지 재사용.
            log.info("memberJoinDTO = 4-2 MemberServiceImpl 기존 이미지 재사용  " + memberJoinDTO);
            Optional<Member> result = memberRepository.findByMid(memberJoinDTO.getMid());
            Member oldMember = result.orElseThrow();
            memberJoinDTO.setUuid(oldMember.getUuid());
            memberJoinDTO.setFileName(oldMember.getFileName());
            log.info("memberJoinDTO = 5 MemberServiceImpl 기존 이미지 재사용  " + memberJoinDTO);
            member = dtoToEntity(memberJoinDTO);
            log.info("memberJoinDTO = 6 MemberServiceImpl 기존 이미지 재사용 member " + member);
            //패스워드는 현재 평문 -> 암호로 변경.
            member.changePassword(passwordEncoder.encode(member.getMpw()));
            // 역할 추가. 기본 USER
            member.addRole(MemberRole.USER);


            // 데이터 가 잘 알맞게 변경이 됐는지 여부,
            log.info("updateMember: " + member);
            log.info("updateMember: " + member.getRoleSet());

            // 디비에 적용하기. -> 수정하기.
            memberRepository.save(member);
        }
         else {
            log.info("memberJoinDTO = 7 MemberServiceImpl 새로운 이미지가 들어오는 경우 memberJoinDTO " + memberJoinDTO);
            //새로운 이미지가 들어오는 경우
            member = dtoToEntity(memberJoinDTO);
            log.info("memberJoinDTO = 8 MemberServiceImpl 새로운 이미지가 들어오는 경우 member " + member);
            //패스워드는 현재 평문 -> 암호로 변경.
            member.changePassword(passwordEncoder.encode(member.getMpw()));
            // 역할 추가. 기본 USER
            member.addRole(MemberRole.USER);


            // 데이터 가 잘 알맞게 변경이 됐는지 여부,
            log.info("updateMember: " + member);
            log.info("updateMember: " + member.getRoleSet());

            // 디비에 적용하기. -> 수정하기.
            memberRepository.save(member);
        }


    }

    @Override
    public void updateSocial(String mid, String mpw) throws MidExistException {
        //기존 아이디와 중복되는지 여부 확인
        Optional<Member> result = memberRepository.findByEmail(mid);
        Member member = result.orElseThrow();

        // 중복이 아니니 회원 가입 처리하기.
//         Member member = modelMapper.map(memberJoinDTO, Member.class);
        log.info("mid = 4 MemberServiceImpl 프로필 이미지 있는 경우  " + mid);
//        Member member = dtoToEntity(memberJoinDTO);
        //패스워드는 현재 평문 -> 암호로 변경.
        member.changePassword(passwordEncoder.encode(mpw));
        // 역할 추가. 기본 USER
        member.addRole(MemberRole.USER);


        // 데이터 가 잘 알맞게 변경이 됐는지 여부,
        log.info("updateMember: " + member);
        log.info("updateMember: " + member.getRoleSet());

        // 디비에 적용하기. -> 수정하기.
        memberRepository.save(member);
    }

    @Override
    public UploadResultDTO uploadProfileImage(MultipartFile fileImageName) {
        log.info("MemberServiceImpl uploadFileDTO : " + fileImageName);
        if (fileImageName != null) {
            //multipartFile 객체 안에 이미지 파일들이 들어가 있다.
            log.info("파일명 확인: " + fileImageName.getOriginalFilename());
            //원본 파일명
            String originName = fileImageName.getOriginalFilename();
            // 랜덤한 16자리 문자열
            String uuid = UUID.randomUUID().toString();
            // 업로드 경로에 파일 객체를 만들기.
            Path savePath = Paths.get(uploadPath, uuid + "_" + originName);

            boolean imgCheck = false;

            try {
                //실제 파일에 저장.
                fileImageName.transferTo(savePath);

                //해당 파일의 종류를 확인하고, 타입 image/* 로 시작한다면
                // 썸네일로 변경하기.
                if (Files.probeContentType(savePath).startsWith("image")) {
                    // 이미지 상태 변수 변경.
                    imgCheck = true;
                    // uploadPath 해당 경로에 , 물리 파일 만들기 , 이름 :"s_"+uuid+"_"+originName
                    File thumbFile = new File(uploadPath, "s_" + uuid + "_" + originName);
                    // 원본 이미지 -> thumbFile 곳에 축소해서 저장하기.
                    Thumbnailator.createThumbnail(savePath.toFile(), thumbFile, 200, 200);
                }

            } catch (IOException e) {
                e.printStackTrace();
            }

            //각각 이미지 파일명, 임시 목록에 담기.


            UploadResultDTO uploadResultDTO = UploadResultDTO.builder()
                    .uuid(uuid)
                    .fileName(originName)
                    .imgCheck(imgCheck)
                    .build();




            return uploadResultDTO;
        } // if 파일(사진)이 있는 경우
        // 파일(사진)이 없을 경우
        return null;
    }
}
