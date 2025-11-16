package com.busanit501.boot501.repository;

import com.busanit501.boot501.domain.Board;
import com.busanit501.boot501.domain.Reply;
import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@SpringBootTest
@Log4j2
public class ReplyRepositoryTest {
    @Autowired
    private ReplyRepository replyRepository;

    @Test
    public void testInsert() {
        //실제 디비 각자 데이터에 따라서 다름.
        // 현재 bno = 900
        Long bno = 1L;

        Board board = Board.builder()
                .bno(bno)
                .build();

        Reply reply = Reply.builder()
                .board(board)
                .replyText("오늘 점심은 면으로")
                .replyer("이상용")
                .build();

        replyRepository.save(reply);

    } //

    @Transactional
    @Test
    public void testBoardReplies() {
        // 각자 테이블의 데이터 내용에 맞게.
        Long bno = 18L;

        Pageable pageable =
                PageRequest.of(0,10,
                        Sort.by("rno").descending());

//       Page<Reply> result = replyRepository.listOfBoard(bno,pageable);
        Optional<Reply> result = replyRepository.findById(bno);
        List<Reply> result2 = replyRepository.findByBoardBno(bno);

//        Reply reply = result.orElseThrow();
        log.info("reply 확인 : " +result.isEmpty());
        log.info("reply2 확인 : " +result2.isEmpty());
//       result.getContent().forEach(reply -> {
//           log.info("reply 확인 : " +reply);
//       });

    }

}
