package com.busanit501.boot501.repository;

import com.busanit501.boot501.domain.Reply;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface ReplyRepository extends JpaRepository<Reply, Long> {
    @Query("select r from Reply r where r.board.bno = :bno")
    Page<Reply> listOfBoard(Long bno, Pageable pageable);

    //삭제 기능.
    void deleteByBoard_Bno (Long bno);

    //추가 기능.
    // 1번 게시글 board_bno 에 있는 모든 댓글 다 조회.
    List<Reply> findByBoardBno(Long bno);
}








