package com.busanit501.boot501.repository;

import com.busanit501.boot501.domain.Board;
import com.busanit501.boot501.domain.BoardImage;
import com.busanit501.boot501.domain.Reply;
import com.busanit501.boot501.dto.BoardListAllDTO;
import com.busanit501.boot501.dto.BoardListReplyCountDTO;
import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.test.annotation.Commit;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.IntStream;

@SpringBootTest
@Log4j2
public class BoardRepositoryTests {

    @Autowired
    BoardRepository boardRepository;
    @Autowired
    ReplyRepository replyRepository;

    @Test
    public void testInsert() {
        IntStream.rangeClosed(1, 100).forEach(i ->
                {
                    Board board = Board.builder()
                            .title("오늘222 점심 뭐 먹지?" + i)
                            .content("한식" + i)
                            .writer("이상용" + (i % 10))
                            .build();
                    // 데이터베이스에 추가,
                    // save 없으면, 1)추가, 있으면, 2) 수정.
                    Board result = boardRepository.save(board);
                    log.info("추가한 BNO: " + result.getBno());

                }
        );

    } // inset test

    @Test
    public void testSelect() {
        Long bno = 100L;
        Optional<Board> result = boardRepository.findById(bno);
        Board board = result.orElseThrow();
        log.info("조회 결과 : " + board);
    }

    @Test
    public void testUpdate() {
        Long bno = 100L;
        Optional<Board> result = boardRepository.findById(bno);
        Board board = result.orElseThrow();

        log.info("조회 결과1 전 : " + board);
        board.changeTitleAndContent("오늘 점심 뭐 먹죠 수정버전", "로제 떡볶이, 냉라면, 족발");
        // 반영.
        boardRepository.save(board);
        log.info("조회 결과2 후: " + board);

    }

    @Test
    public void testDelete() {
        Long bno = 100L;
        // 반영.
        boardRepository.deleteById(100L);
        log.info("조회 결과2 후: 디비상에서 삭제 여부 확인 하기.");
    }

    //페이징 테스트
    @Test
    public void testPaging() {
//   준비물 준비
        // 첫번째 파라미터 :페이지수(1페이지 , 0)
        // 두번째 파라미터 :페이지 당 보여줄 갯수(10개)
        // 세번째 파라미터 :정렬 기준, bno , 내림차순.
        Pageable pageable = PageRequest.of(0, 10, Sort.by("bno").descending());
        // 10개씩 조회 해보기.
        //Page 타입이라는 것은, 해당 결과에, 여러 정보들이 있음.
        // 예) 10개씩 가져온 데이터, 2)페이지 정보, 3)갯수, 4)전체 갯수 등.
        Page<Board> result = boardRepository.findAll(pageable);

        // 담겨진 페이징 관련 결과를 출력및 알아보기.
        log.info("전체 갯수 total  result.getTotalElements() : " + result.getTotalElements());
        log.info("전체 페이지  result.getTotalPages() : " + result.getTotalPages());
        log.info("페이지 number  result.getNumber() : " + result.getNumber());
        log.info("페이지 당 불러올 수  result.getSize() : " + result.getSize());
        log.info("불러올 데이터 목록  result.getContent() : ");
        // 불러올 목록 데이터를 받아서 처리해보기.
        List<Board> list = result.getContent();
        list.forEach(board -> log.info(board));

    }

    // Querydsl 이용해서 , 조회해보기.
    @Test
    public void testSearch() {

        Pageable pageable = PageRequest.of(1, 10, Sort.by("bno").descending());
        // 실행 여부를 확인 해보기.
        boardRepository.search(pageable);
    }

    // Querydsl 이용해서 , 검색, 페이징 이용해서 조회해보기
    @Test
    public void testSearchAll() {

        // 검색 조건 더미 데이터
        String[] types = {"t", "w", "c"};
        // 검색 조건 더미 데이터2, 키워드
        String keyword = "점심";

        Pageable pageable = PageRequest.of(1, 10, Sort.by("bno").descending());

        // 실행 여부를 확인 해보기.
        // 결과를 반환 타입 Page 받기.
        Page<Board> result = boardRepository.searchAll(types, keyword, pageable);

        // 페이징 된 결과물 확인.
        // 담겨진 페이징 관련 결과를 출력및 알아보기.
        log.info("Querydsl 결과 : 전체 갯수 total  result.getTotalElements() : " + result.getTotalElements());
        log.info("Querydsl 결과 : 전체 페이지  result.getTotalPages() : " + result.getTotalPages());
        log.info("Querydsl 결과 : 페이지 number  result.getNumber() : " + result.getNumber());
        log.info("Querydsl 결과 : 페이지 당 불러올 수  result.getSize() : " + result.getSize());
        log.info("Querydsl 결과 : 불러올 데이터 목록  result.getContent() : ");
        log.info("Querydsl 결과 : 이전 페이지  존재 여부  result.hasPrevious() : " + result.hasPrevious());
        log.info("Querydsl 결과 : 다음 페이지  존재 여부  result.hasNext() : " + result.hasNext());
        // 불러올 목록 데이터를 받아서 처리해보기.
        List<Board> list = result.getContent();
        list.forEach(board -> log.info(board));
    }

    // Querydsl 이용해서 , 검색, 페이징 이용해서 조회해보기
    // 댓글의 갯수를 포함한 검색 테스트
    @Test
    public void testSearchReplyCount() {

        // 검색 조건 더미 데이터
        String[] types = {"t", "w", "c"};
        // 검색 조건 더미 데이터2, 키워드
        String keyword = "점심";

        Pageable pageable = PageRequest.of(0, 10, Sort.by("bno").descending());

        // 실행 여부를 확인 해보기.
        // 결과를 반환 타입 Page 받기.
        Page<BoardListReplyCountDTO> result =

                boardRepository.searchWithReplyCount(types, keyword, pageable);

        // 페이징 된 결과물 확인.
        // 담겨진 페이징 관련 결과를 출력및 알아보기.
        log.info("Querydsl 결과 : 전체 갯수 total  result.getTotalElements() : " + result.getTotalElements());
        log.info("Querydsl 결과 : 전체 페이지  result.getTotalPages() : " + result.getTotalPages());
        log.info("Querydsl 결과 : 페이지 number  result.getNumber() : " + result.getNumber());
        log.info("Querydsl 결과 : 페이지 당 불러올 수  result.getSize() : " + result.getSize());
        log.info("Querydsl 결과 : 불러올 데이터 목록  result.getContent() : ");
        log.info("Querydsl 결과 : 이전 페이지  존재 여부  result.hasPrevious() : " + result.hasPrevious());
        log.info("Querydsl 결과 : 다음 페이지  존재 여부  result.hasNext() : " + result.hasNext());
        // 불러올 목록 데이터를 받아서 처리해보기.
        List<BoardListReplyCountDTO> list = result.getContent();
        list.forEach(board -> log.info(board));
    }

    // 보드 게시글의 첨부 이미지들 추가 테스트
    @Test
    public void testInsertWithImages() {
        // 더미 데이터 만들기.
        // 부모 더미 데이터 board , 0x100
        Board board = Board.builder()
                .title("오늘 점심 뭐 먹죠? 생각중. 한식쟁이 밥이 생각남")
                .content("국밥, 된장찌개, 비빔밥")
                .writer("이상용")
                .build();

        //더미 데이터, 임의 사진을 추가 해보기.
        for (int i = 0; i < 3; i++) {
            String uuid = UUID.randomUUID().toString();
            String fileName = "SampleImageFileName";
            board.addImage(uuid, fileName + i + ".png");
        }
        boardRepository.save(board);

    }

    // 게시글의 첨부 이미지들 조회시, 성능 확인 테스트
    @Test
    @Transactional
    public void testReadWithImages() {
        //더미 데이터 2개, 게시글 1, 2번
//    Optional<Board> result = boardRepository.findById(1L);
        Optional<Board> result = boardRepository.findByIdWithImages(1L);
        Board board = result.orElseThrow();

        // 보드 출력해보기. 1차 캐시 테이블에서, 더티 체킹, select
        // 단위 테스트 할 때, board 조회 할 때 세션이 하나 필요하고
        // 단위 테스트 할 때, boardImage 이미지 조회 할 때 세션이 하나 더 필요하고
        // 단위 테스트 이용시에는 디비 접근 세션을 하나만 이용해서, 오류가 발생함.

        log.info("BoardRepositoryTests board 확인  : " + board);
        log.info("========================================== ");
        log.info("BoardRepositoryTests board.getImageSet() 확인2  : " + board.getImageSet());
        // 1차 오류 발생함.
        for (BoardImage boardImage : board.getImageSet()) {
            log.info("BoardRepositoryTests board.getImageSet() 확인32  : " + boardImage);
        }

    }

    // 세션을 추가로 이용 가능함.
    @Transactional
    //단위 테스트에서, 수정을 반영하기.
    @Commit
    @Test
    public void testUpdateImages() {
        Optional<Board> result = boardRepository.findByIdWithImages(1L);
        Board board = result.orElseThrow();

        // 이미지 수정시, 기존 이미지를 전부 다 삭제 후 새로 추가하기.
        board.clearImages();

        // 새 첨부 이미지 추가하기.
        for (int i = 0; i < 2; i++) {
            String uuid = UUID.randomUUID().toString();
            String fileName = "SampleImageFileName_수정2";
            board.addImage(uuid, fileName + i + ".png");
        }
        boardRepository.save(board);
    }

  @Test
  @Transactional
  @Commit
  public void testDeleteAll() {
      Long bno = 1L;
      // 게시글에 대한 댓글 삭제
      replyRepository.deleteByBoard_Bno(bno);
      // 게시글 삭제
      boardRepository.deleteById(bno);

  }

  // 더미 데이터 추가, 댓글도 추가, 이미지들도 추가하기.
    @Transactional
    @Commit
    @Test
    public void testInsertAll() {
        for(int i = 1; i <=100 ; i++){
            Board board = Board.builder()
                    .title("샘플 데이터 " + i)
                    .content("샘플 제목 " + i)
                    .writer("이상용"+i)
                    .build();

            for (int j=0; j<3; j++){
                if(i % 5 ==0) {
                    // 5번째 씩 , 첨부 이미지 추가 안하기.
                    continue;
                }
                // 첨부 이미지 3장씩 더미데이터
                String uuid = UUID.randomUUID().toString();
                String fileName = "샘플 이미지";
                board.addImage(uuid,fileName+j+".png");


            }
            // 게시글 작성 후 ,
            boardRepository.save(board);
            // 댓글 달기.
            for (int j=0; j<3; j++) {
                Reply reply = Reply.builder()
                        .board(board)
                        .replyText("샘플 댓글" + j)
                        .replyer("이상용")
                        .build();
                replyRepository.save(reply);
            }



    }


    }

    // N+1 문제 확인용 단위테스트 메서드추가
    @Transactional
    @Test
    public void testSearchWithAll() {
        Pageable pageable = PageRequest.of(0,10,
                Sort.by("bno").descending());
        boardRepository.searchWithAll(null,null,pageable);
    }

    @Transactional
    @Test
    public void testSearchWithAll2() {
        Pageable pageable = PageRequest.of(0,10,
                Sort.by("bno").descending());

        //
        Page<BoardListAllDTO> result = boardRepository.searchWithAll(null,null,pageable);
        // 전체 갯수
        log.info("test, result.getTotalElements() 확인1 : " + result.getTotalElements());
        // 각 목록의 요소 확인.
        result.getContent().forEach(boardListAllDTO -> {
            log.info("boardListAllDTO, 각 요소 확인2 : " + boardListAllDTO);
        });


    }

    @Transactional
    @Test
    public void testSearchWithAll3() {
        Pageable pageable = PageRequest.of(0,10,
                Sort.by("bno").descending());

        //더미 타입, 키워드 조건 재사용.
        // 검색 조건 더미 데이터
        String[] types = {"t", "w", "c"};
        // 검색 조건 더미 데이터2, 키워드
        String keyword = "샘플";
        //
        Page<BoardListAllDTO> result = boardRepository.searchWithAll(types,keyword,pageable);
        // 전체 갯수
        log.info("testSearchWithAll3, result.getTotalElements() 확인1 : " + result.getTotalElements());
        // 각 목록의 요소 확인.
        result.getContent().forEach(boardListAllDTO -> {
            log.info("testSearchWithAll3, boardListAllDTO, 각 요소 확인2 : " + boardListAllDTO);
        });


    }



}







