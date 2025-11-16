package com.busanit501.boot501.service;

import com.busanit501.boot501.domain.Board;
import com.busanit501.boot501.domain.Reply;
import com.busanit501.boot501.dto.*;
import com.busanit501.boot501.repository.BoardRepository;
import com.busanit501.boot501.repository.ReplyRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.modelmapper.ModelMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@Log4j2
@RequiredArgsConstructor
// all or nothing,
@Transactional
public class BoardServiceImpl implements BoardService {
  // 의존성 주입
  private final BoardRepository boardRepository;
  private final ReplyRepository replyRepository;
  private final ModelMapper modelMapper;

  @Override
  public Long register(BoardDTO boardDTO) {
    // 화면에서 작성한 게시글 내용이 DTO 있고, -> VO 대신 entity 클래스 이용중.
//    Board board = modelMapper.map(boardDTO, Board.class);
    // 첨부 이미지들이 추가 후, 메서드 변경
    Board board = dtoToEntity(boardDTO);
    Long bno = boardRepository.save(board).getBno();
    return bno;
  }

  @Override
  public BoardDTO read(Long bno) {
    // 1차 영속성 컨텍스트에서 조회한 내용을 가져오기.
//    Optional<Board> result = boardRepository.findById(bno);
    // 이미지 첨부 버전으로 수정하기.
    Optional<Board> result = boardRepository.findByIdWithImages(bno);
    // 만약 있다면, 엔티티 타입으로 담기.(VO 같은 개념)
    Board board = result.orElseThrow();
    // 엔티티 -> DTO 변환.
    //BoardDTO boardDTO = modelMapper.map(board, BoardDTO.class);
    // 이미지 추가 버전으로 변경하기.
    BoardDTO boardDTO = entityToDTO(board);

    return boardDTO;
  }

  @Override
  public void update(BoardDTO boardDTO) {
    Optional<Board> result = boardRepository.findById(boardDTO.getBno());
    Board board = result.orElseThrow();
    // 만약 변경한다면, 제목과 내용만 변경하기. ,엔티티 클래스에서 메서드로 만듦.
    board.changeTitleAndContent(boardDTO.getTitle(),boardDTO.getContent());

    // 첨부 이미지 파일 추가, 포인트 : 기존 이미지 삭제 후, 새로운 이미지 추가.
    // 기존 이미지 파일 삭제
    board.clearImages();

    // 새로운 이미지 추가하기.
    if(boardDTO.getFileNames() != null) {
      for(String fileName : boardDTO.getFileNames()){
        String[] arr = fileName.split("_");
        board.addImage(arr[0],arr[1]);
      }
    }

    // 적용하기.
    boardRepository.save(board);
  }

  @Override
  public void delete(Long bno) {
    // 레스트 방식일 때는 , 유효성 체크해서 없다는 메세지 전달해줘야 함.
//    Optional<Board> result = boardRepository.findById(bno);
//    Board board = result.orElseThrow();
    boardRepository.deleteById(bno);
  }

  @Override
  public void deleteAll(Long bno) {
    // 레스트 방식일 때는 , 유효성 체크해서 없다는 메세지 전달해줘야 함.
//    Optional<Board> result = boardRepository.findById(bno);
//    Board board = result.orElseThrow();

    // 게시글에 대한 댓글을 삭제하고,
    // Reply 테이블에는 bno 필드가 없고, board_bno 있음.
    // 그래서, 매번 실행 할 때 마다, null 잡혀서, 우리가 원하는 로직 처리가 안됨
    //
//    Optional<Reply> result = replyRepository.findById(bno);
    List<Reply> result = replyRepository.findByBoardBno(bno);
//    Reply reply = result.orElseThrow();
//    boolean checkReply = reply.getRno() > 0 ? true : false;
    log.info("result.isEmpty() 값  확인:" + result.isEmpty());
    boolean checkReply = result.isEmpty() ? false : true;
    log.info("result.isEmpty() 값  확인2 checkReply:" + checkReply);
    if(checkReply){
      replyRepository.deleteByBoard_Bno(bno);
    }

    //게시글 삭제와 첨부 이미지 삭제(썸네일 이미지 삭제도 포함) 포함
    boardRepository.deleteById(bno);
  }

  @Override
  public PageResponseDTO<BoardDTO> list(PageRequestDTO pageRequestDTO) {
    String[] types = pageRequestDTO.getTypes();
    String keyword = pageRequestDTO.getKeyword();
    Pageable pageable = pageRequestDTO.getPageable("bno");
    // 검색어, 페이징 처리가 된 결과물 10개.
    // VO
    Page<Board> result = boardRepository.searchAll(types,keyword,pageable);
    // Entity(VO) -> DTO
    List<BoardDTO> dtoList = result.getContent().stream()
            .map(board -> modelMapper.map(board,BoardDTO.class))
            .collect(Collectors.toList());

    // 서버 -> 화면에 전달할 준비물 준비 작업 완료.
    // 1)페이지 2) 사이즈 3) 전쳇갯수 4) 검색 결과 내역10개(엔티티-> DTO)
    PageResponseDTO pageResponseDTO = PageResponseDTO.<BoardDTO>withAll()
            .pageRequestDTO(pageRequestDTO)
            .dtoList(dtoList)
            .total((int) result.getTotalElements())
            .build();
    //test

    return pageResponseDTO;
  }

  @Override
  public PageResponseDTO<BoardListReplyCountDTO> listWithReplyCount
          (PageRequestDTO pageRequestDTO) {
    String[] types = pageRequestDTO.getTypes();
    String keyword = pageRequestDTO.getKeyword();
    Pageable pageable = pageRequestDTO.getPageable("bno");

    // 댓글 갯수를 포함한 목록을 가져오기.
    Page<BoardListReplyCountDTO> result = boardRepository.searchWithReplyCount(types,keyword,pageable);
    // BoardListReplyCountDTO 변환 할 필요가 일단 없다.

    // 서버 -> 화면에 전달할 준비물 준비 작업 완료.
    // 1)페이지 2) 사이즈 3) 전쳇갯수 4) 검색 결과 내역10개(엔티티-> DTO)
    PageResponseDTO pageResponseDTO = PageResponseDTO.<BoardListReplyCountDTO>withAll()
            .pageRequestDTO(pageRequestDTO)
            .dtoList(result.getContent())
            .total((int) result.getTotalElements())
            .build();

    return pageResponseDTO;
  }

  @Override
  public PageResponseDTO<BoardListAllDTO> listWithAll(PageRequestDTO pageRequestDTO) {
    // entity -> dto , 변환하는 방법
    // 1) 모델 맵퍼 맵 함수 이용.
    // 2) Querydsl 에서 projections
    // 3) Querydsl 에서 Tuple 타입을 만들기.
    // 파이썬 , 컬렉션과 비슷, 모음집, 복수개.
    String[] types = pageRequestDTO.getTypes();
    String keyword = pageRequestDTO.getKeyword();
    Pageable pageable = pageRequestDTO.getPageable("bno");

    Page<BoardListAllDTO> result = boardRepository.searchWithAll(types,keyword,pageable);

    PageResponseDTO<BoardListAllDTO> pageResponseDTO =
            PageResponseDTO.<BoardListAllDTO>withAll()
                    .pageRequestDTO(pageRequestDTO)
                    .dtoList(result.getContent())
                    .total((int) result.getTotalElements())
                    .build();

    return pageResponseDTO;
  }
}







