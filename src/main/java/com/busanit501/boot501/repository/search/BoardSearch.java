package com.busanit501.boot501.repository.search;

import com.busanit501.boot501.domain.Board;
import com.busanit501.boot501.dto.BoardListAllDTO;
import com.busanit501.boot501.dto.BoardListReplyCountDTO;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface BoardSearch {
  Page<Board> search(Pageable pageable);

  Page<Board> searchAll(String[] types, String keyword ,Pageable pageable);

  // 댓글 개수를 포함한 전체 게시글 목록.
  Page<BoardListReplyCountDTO> searchWithReplyCount(
          String[] types, String keyword ,Pageable pageable
  );

  // 댓글, 첨부 이미지들도 같이 조회
//  Page<BoardListReplyCountDTO> searchWithAll(
//          String[] types, String keyword ,Pageable pageable
//  );

  Page<BoardListAllDTO> searchWithAll(
          String[] types, String keyword ,Pageable pageable
  );

}













