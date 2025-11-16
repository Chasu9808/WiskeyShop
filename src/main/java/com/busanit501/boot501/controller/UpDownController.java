package com.busanit501.boot501.controller;

import com.busanit501.boot501.dto.upload.UploadFileDTO;
import com.busanit501.boot501.dto.upload.UploadProfileFileDTO;
import com.busanit501.boot501.dto.upload.UploadResultDTO;
import lombok.extern.log4j.Log4j2;
import net.coobird.thumbnailator.Thumbnailator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

@RestController
@Log4j2
public class UpDownController {
    @Value("${com.busanit501.upload.path}")
    private String uploadPath;

//    @Tag(name = "파일 업로드 post 방식", description = "파일 업로드 post 방식")
    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public List<UploadResultDTO> upload(UploadFileDTO uploadFileDTO){
        log.info("UpDownController에서 uploadFileDTO : "+uploadFileDTO);
        if(uploadFileDTO.getFiles() != null) {
            //임시로 담아둘 이미지 파일 목록 저장소
            final List<UploadResultDTO> imgList = new ArrayList<>();

            uploadFileDTO.getFiles().forEach(multipartFile -> {
                //multipartFile 객체 안에 이미지 파일들이 들어가 있다.
                log.info("파일명 확인: "+multipartFile.getOriginalFilename());
                //원본 파일명
                String originName = multipartFile.getOriginalFilename();
                // 랜덤한 16자리 문자열
                String uuid = UUID.randomUUID().toString();
                // 업로드 경로에 파일 객체를 만들기.
                Path savePath = Paths.get(uploadPath,uuid+"_"+originName);

                boolean imgCheck = false;

                try{
                    //실제 파일에 저장.
                    multipartFile.transferTo(savePath);

                    //해당 파일의 종류를 확인하고, 타입 image/* 로 시작한다면
                    // 썸네일로 변경하기.
                    if(Files.probeContentType(savePath).startsWith("image")){
                        // 이미지 상태 변수 변경.
                        imgCheck = true;
                        // uploadPath 해당 경로에 , 물리 파일 만들기 , 이름 :"s_"+uuid+"_"+originName
                        File thumbFile = new File(uploadPath, "s_"+uuid+"_"+originName);
                        // 원본 이미지 -> thumbFile 곳에 축소해서 저장하기.
                        Thumbnailator.createThumbnail(savePath.toFile(),thumbFile,200,200);
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

                imgList.add(uploadResultDTO);

            }); //foreach
            return imgList;
        } // if 파일(사진)이 있는 경우
        // 파일(사진)이 없을 경우
        return null;
    } //업로드

    //프로필 업로드용으로 변경
    @PostMapping(value = "/uploadProfile", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public UploadResultDTO uploadProfile(UploadProfileFileDTO uploadProfileFileDTO){
        log.info("UpDownController에서 uploadFileDTO : "+uploadProfileFileDTO);
        if(uploadProfileFileDTO.getFile() != null) {
            //임시로 담아둘 이미지 파일 목록 저장소
//            final List<UploadResultDTO> imgList = new ArrayList<>();
           MultipartFile multipartFile = uploadProfileFileDTO.getFile();
//            uploadFileDTO.getFiles().forEach(multipartFile -> {
                //multipartFile 객체 안에 이미지 파일들이 들어가 있다.
                log.info("파일명 확인: "+multipartFile.getOriginalFilename());
                //원본 파일명
                String originName = multipartFile.getOriginalFilename();
                // 랜덤한 16자리 문자열
                String uuid = UUID.randomUUID().toString();
                // 업로드 경로에 파일 객체를 만들기.
                Path savePath = Paths.get(uploadPath,uuid+"_"+originName);

                boolean imgCheck = false;

                try{
                    //실제 파일에 저장.
                    multipartFile.transferTo(savePath);

                    //해당 파일의 종류를 확인하고, 타입 image/* 로 시작한다면
                    // 썸네일로 변경하기.
                    if(Files.probeContentType(savePath).startsWith("image")){
                        // 이미지 상태 변수 변경.
                        imgCheck = true;
                        // uploadPath 해당 경로에 , 물리 파일 만들기 , 이름 :"s_"+uuid+"_"+originName
                        File thumbFile = new File(uploadPath, "s_"+uuid+"_"+originName);
                        // 원본 이미지 -> thumbFile 곳에 축소해서 저장하기.
                        Thumbnailator.createThumbnail(savePath.toFile(),thumbFile,200,200);
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



//            }); //foreach
            return uploadResultDTO;
        } // if 파일(사진)이 있는 경우
        // 파일(사진)이 없을 경우
        return null;
    } //업로드

    @GetMapping(value = "/view/{fileName}")
    public ResponseEntity<Resource> getViewFile(@PathVariable String fileName){
        // 스프링 코어 기능에서,
        // c:\\upload\\springTest\\이미지파일명, 접근 하는 객체
        Resource resource = new FileSystemResource(
                 uploadPath+File.separator+fileName);
        String resourceName = resource.getFilename();
        // http 헤더 객체를 이용해서 추가 옵션
        HttpHeaders headers = new HttpHeaders();
        try {
            // 해당 이미지의 타입 : "image/png", "image/jpg"
            headers.add("Content-Type",
                    Files.probeContentType(resource.getFile().toPath()));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
        return ResponseEntity.ok().headers(headers).body(resource);
    } // 이미지 하나 조회

    @DeleteMapping(value = "/delete/{fileName}")
    public Map<String,Boolean> deleteFile(@PathVariable String fileName) throws IOException {
        // c:\\upload\\springTest\\이미지파일명, 접근 하는 객체
        Resource resource = new FileSystemResource(
                uploadPath+File.separator+fileName);
        String resourceName = resource.getFilename();
        // 결과 알려줄 임시 맵
        Map<String,Boolean> resultMap = new HashMap<>();
        boolean deleteCheck = false;
        try {
            // 원본 파일 삭제
            // contentType , 섬네일 삭제시 이용할 예정.
            String contentType = Files.probeContentType(resource.getFile().toPath());
            deleteCheck = resource.getFile().delete();
            if(contentType.startsWith("image")){
                File thumbnailFile = new File(uploadPath+File.separator
                        +"s_"+fileName);
                thumbnailFile.delete();
            }
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        resultMap.put("result",deleteCheck);
        return resultMap;
    }




}
