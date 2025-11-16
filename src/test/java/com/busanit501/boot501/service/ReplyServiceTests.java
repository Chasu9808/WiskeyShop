package com.busanit501.boot501.service;

import com.busanit501.boot501.domain.Board;
import com.busanit501.boot501.dto.ReplyDTO;
import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
@Log4j2
public class ReplyServiceTests {
    @Autowired
    private ReplyService replyService;

    @Test
    public void testInsert() {



        // 작성할 더미 댓글 필요함.
        ReplyDTO replyDTO = ReplyDTO.builder()
                .bno(902L)
                .replyText("오늘 점심? 회밀면")
                .replyer("이상용")
                .build();
        Long rno = replyService.register(replyDTO);
        log.info("작성한 댓글 번호 : " + rno);
    }

}
