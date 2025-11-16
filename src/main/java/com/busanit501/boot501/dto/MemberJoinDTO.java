package com.busanit501.boot501.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class MemberJoinDTO {
    private String mid;
    private String mpw;
    private String email;
//    private boolean del;
//    private boolean social;

    private String memberName;
    private String address;

    private String uuid;
    private String fileName;
    //첨부 파일 이름들
    // fileNames, uuid_fileName 구조 되어 있고,
    // 업로드 후, 해당 dto에 위의 이름 구조 파일형식으로 업로드 하기.
    private List<String> fileNames;
//    private MultipartFile profileImage;
    public void addProfileImage(String fileName) {
        this.fileNames.add(fileName);
    }

}
