package com.busanit501.boot501.service;

import com.busanit501.boot501.domain.Board;
import com.busanit501.boot501.dto.*;
import com.busanit501.boot501.repository.BoardRepository;
import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@SpringBootTest
@Log4j2
public class BoardServiceTests {
  @Autowired
  BoardService boardService;
  @Autowired
  BoardRepository boardRepository;

  @Test
  public void testInsert() {
    // 화면에서 넘어온 더미 데이터 만들기. DTO 타입.
    BoardDTO boardDTO = BoardDTO.builder()
        .title("내일 모하니?")
        .content("부모님 인사하기")
        .writer("이상용")
        .build();

    Long bno = boardService.register(boardDTO);
    log.info("추가 후에 반환 게시글 번호 bno : " + bno);

  }

  @Test
  public void testRead() {

    BoardDTO boardDTO = boardService.read(601L);
    log.info("하나 조회 boardDTO : " + boardDTO);

  }

  @Test
  public void testUpdate() {
    // 변경시, 변경할 더미 데이터, 임시, 601L
// 화면에서 넘어온 더미 데이터 만들기. DTO 타입.
    BoardDTO boardDTO = BoardDTO.builder()
        .bno(601L)
        .title("내일 모하니?수정버전")
        .content("부모님 인사하기 : 수정버전")
        .writer("이상용 : 수정버전")
        .build();

    //디비에서 조회하기.
    boardService.update(boardDTO);


  }


  @Test
  public void testDelete() {
        //디비에서 조회하기.
    // 좋은 질문,
    // 서버에서 화면, 데이터 같이 처리, Controller,
    // 질문, 게시글 삭제 할려면, 화면에 보일까요? 안보일까요?

    // RestController, 데이터만 처리.
    // 화면이 없어서, method delete 형식으로 명령이 오면,
    boardService.delete(601L);


  }

  @Test
  public void testList() {
    // 화면에서 전달할 내용을 담은 PageRequestDTO 더미가 필요.
    PageRequestDTO pageRequestDTO = PageRequestDTO.builder()
            .type("tcw")
            .keyword("오늘")
            .page(1)
            .size(10)
            .build();

  PageResponseDTO<BoardDTO> responseDTO = boardService.list(pageRequestDTO);
    log.info("list 테스트 responseDTO : " + responseDTO);

  }


  @Test
  public void testListWithCount() {
    // 화면에서 전달할 내용을 담은 PageRequestDTO 더미가 필요.
    PageRequestDTO pageRequestDTO = PageRequestDTO.builder()
            .type("tcw")
            .keyword("오늘")
            .page(1)
            .size(10)
            .build();

    PageResponseDTO<BoardListReplyCountDTO> responseDTO = boardService.listWithReplyCount(pageRequestDTO);
    log.info("list 테스트 responseDTO : " + responseDTO);

  }

  @Test
  public void testRegisterWithImages() {
    BoardDTO boardDTO = BoardDTO.builder()
            .title("샘플 제목입니다.")
            .content("샘플 내용입니다.")
            .writer("이상용")
            .build();

    // 더미 이미지들
    boardDTO.setFileNames(
            Arrays.asList(
                  //파일명,
                    UUID.randomUUID()+"_testImage.png",
                    UUID.randomUUID()+"_testImage2.png",
                    UUID.randomUUID()+"_testImage3.png"
            )
    ); // 더미 이미지 파일명 추가

    Long bno = boardService.register(boardDTO);
    log.info("boardService, register 확인 bno : " + bno);
  }

  @Test
  public void testReadWithImage() {

    BoardDTO boardDTO = boardService.read(104L);
    log.info("testReadWithImage, 하나 조회 boardDTO : " + boardDTO);
    for(String fileImage : boardDTO.getFileNames()){
      log.info("각 이미지 파일명만 조회 : " + fileImage);
    }

  }

  @Test
  public void testUpdateWithImages() {
    // 변경시, 변경할 더미 데이터, 임시, 601L
// 화면에서 넘어온 더미 데이터 만들기. DTO 타입.
    BoardDTO boardDTO = BoardDTO.builder()
            .bno(104L)
            .title("내일 모하니?수정버전")
            .content("부모님 인사하기 : 수정버전")
            .build();

    // 더미 데이터에 첨부 이미지 파일 추가.
    boardDTO.setFileNames(
            Arrays.asList(
                    UUID.randomUUID()+"_sampleImage.png",
                    UUID.randomUUID()+"_sampleImage2.png"
            )
    );

    //디비에서 조회하기.
    boardService.update(boardDTO);


  }

  @Test
  public void deleteAll() {
    boardService.deleteAll(103L);

  }

  @Test
  public void testListAll() {
    // 화면에서 전달할 내용을 담은 PageRequestDTO 더미가 필요.
    PageRequestDTO pageRequestDTO = PageRequestDTO.builder()
            .type("tcw")
            .keyword("샘플")
            .page(1)
            .size(10)
            .build();

    PageResponseDTO<BoardListAllDTO> responseDTO =
            boardService.listWithAll(pageRequestDTO);

    // 이미지들 만 뽑아 보기..
    List<BoardListAllDTO> dtoList = responseDTO.getDtoList();
    dtoList.forEach(boardListAllDTO -> {
      log.info("제목 : " + boardListAllDTO.getTitle());
      if(boardListAllDTO.getBoardImages() !=null ) {
        for (BoardImageDTO boardImageDTO : boardListAllDTO.getBoardImages()) {
          log.info("이미지들 목록중에서 하나씩 꺼내서 파일명 조회 : " + boardImageDTO);
        }
      }
    });

    log.info("testListAll 테스트 responseDTO : " + responseDTO);

  }

}







