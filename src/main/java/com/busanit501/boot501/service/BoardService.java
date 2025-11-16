package com.busanit501.boot501.service;

import com.busanit501.boot501.domain.Board;
import com.busanit501.boot501.dto.*;
import lombok.extern.log4j.Log4j2;


import java.util.List;
import java.util.stream.Collectors;


public interface BoardService {
  Long register(BoardDTO boardDTO);
  //하나 조회, read
  BoardDTO read(Long bno);

  void update(BoardDTO boardDTO);
  void delete(Long bno);
  void deleteAll(Long bno);

  // 화면에서, 사용자가, 현재 페이지 12, 사이지 : 10개 씩 보고
  // 검색어가 존재하고, 타입도 있고,
  PageResponseDTO<BoardDTO> list(PageRequestDTO pageRequestDTO);
  //댓글 숫자 포함해서 목록 출력하기.
  PageResponseDTO<BoardListReplyCountDTO> listWithReplyCount(PageRequestDTO pageRequestDTO);

  // 댓글 갯수 + 첨부 이미지들
  PageResponseDTO<BoardListAllDTO> listWithAll(PageRequestDTO pageRequestDTO);

  //원래, 옛날 버전의 인터페이스는 구성품이, 상수와 추상메서드로만 구성이 되었음.
  // 하지만, jdk 버전 업이 되면서, 디폴트 메서드(일반메서드), private 메서드등을
  // 가질수 있다.
  default Board dtoToEntity(BoardDTO boardDTO){

    Board board = Board.builder()
            .bno(boardDTO.getBno())
            .title(boardDTO.getTitle())
            .content(boardDTO.getContent())
            .writer(boardDTO.getWriter())
            .build();

    // 첨부 이미지들이 추가
    if(boardDTO.getFileNames() != null) {
      boardDTO.getFileNames().forEach(fileName ->
      {
        String[] arr = fileName.split("_");
        board.addImage(arr[0],arr[1]);
      }); // forEach 닫기
    } // if 닫기
    return board;
  } // dtoToEntity 닫기.

  // entityToDTO
  // 화면(DTO) ->  컨트롤러 ->서비스(각 변환작업을함.) - Entity 타입으로 - DB
  default BoardDTO entityToDTO(Board board) {
    BoardDTO boardDTO = BoardDTO.builder()
            .bno(board.getBno())
            .title(board.getTitle())
            .content(board.getContent())
            .writer(board.getWriter())
            .regDate(board.getRegDate())
            .modDate(board.getModDate())
            .build();

    // 첨부된 이미지 파일들.
    List<String> fileNames = board.getImageSet().stream().sorted().map(
            boardImage -> boardImage.getUuid()+"_"+boardImage.getFileName()
    ).collect(Collectors.toList());

    boardDTO.setFileNames(fileNames);

    return boardDTO;
  }



}







