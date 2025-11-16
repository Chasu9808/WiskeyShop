package com.busanit501.boot501.dto;

import lombok.Data;

import java.time.LocalDateTime;

@Data
public class BoardListReplyCountDTO {
    private Long bno;
    private String title;
    private String writer;
    private LocalDateTime regDate;
    //댓글 갯수 표기 하기 위한 용도.
    private Long replyCount;
}
