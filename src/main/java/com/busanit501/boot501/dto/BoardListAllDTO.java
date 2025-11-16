package com.busanit501.boot501.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class BoardListAllDTO {
    private Long bno;
    private String title;
    private String writer;
    private LocalDateTime regDate;
    //댓글 갯수 표기 하기 위한 용도.
    private Long replyCount;
    // 첨부 이미지들
    private List<BoardImageDTO> boardImages;
}
