package com.busanit501.boot501.service;

import com.busanit501.boot501.domain.Board;
import com.busanit501.boot501.domain.Reply;
import com.busanit501.boot501.dto.PageRequestDTO;
import com.busanit501.boot501.dto.PageResponseDTO;
import com.busanit501.boot501.dto.ReplyDTO;
import com.busanit501.boot501.repository.BoardRepository;
import com.busanit501.boot501.repository.ReplyRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.modelmapper.ModelMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Log4j2
public class ReplyServiceImpl implements ReplyService {

    private final ReplyRepository replyRepository;
    private final BoardRepository boardRepository;
    private final ModelMapper modelMapper;

    @Override
    public Long register(ReplyDTO replyDTO) {
        Reply reply = modelMapper.map(replyDTO, Reply.class);
        // replyDTO 들어 있는 게시글 번호로, 해당 엔티티 객체를 가지고 오기.
        Optional<Board> result = boardRepository.findById(replyDTO.getBno());
        Board board = result.orElseThrow();
        reply.setBoard(board);
        Long rno = replyRepository.save(reply).getRno();

        return rno;
    }

    @Override
    public ReplyDTO read(Long rno) {
        Optional<Reply> replyOptional = replyRepository.findById(rno);
        Reply reply = replyOptional.orElseThrow();
        log.info("확인1 Read reply: " + reply);
        ReplyDTO replyDTO = modelMapper.map(reply, ReplyDTO.class);
        log.info("확인2 Read replyDTO: " + replyDTO);
        replyDTO.setBno(reply.getBoard().getBno());
        log.info("확인3 Read replyDTO: " + replyDTO);
        return replyDTO;
    }

    @Override
    public void update(ReplyDTO replyDTO) {
        Optional<Reply> replyOptional = replyRepository.findById(replyDTO.getRno());
        Reply reply = replyOptional.orElseThrow();
        reply.chageText(replyDTO.getReplyText());
        replyRepository.save(reply);
    }

    @Override
    public void delete(Long rno) {
        //유효성 체크.
        Optional<Reply> replyOptional = replyRepository.findById(rno);
        Reply reply = replyOptional.orElseThrow();
     replyRepository.deleteById(rno);
    }

    @Override
    public PageResponseDTO<ReplyDTO> getListOfBoard
            (Long bno, PageRequestDTO pageRequestDTO) {
        //페이징 조건 정의하기.
//      Pageable pageable = PageRequest.of(pageRequestDTO.getPage()-1 <=0 ? 0 :pageRequestDTO.getPage()-1,pageRequestDTO.getSize(), Sort.by("rno").descending());
//        Pageable pageable = PageRequest.of(pageRequestDTO.getPage()-1 <=0 ? 0 :pageRequestDTO.getPage()-1, pageRequestDTO.getSize(),Sort.by("rno").descending());
        //오름차순
        Pageable pageable = PageRequest.of(pageRequestDTO.getPage()-1 <=0 ? 0 :pageRequestDTO.getPage()-1, pageRequestDTO.getSize(),Sort.by("rno").ascending());
        Page<Reply> result = replyRepository.listOfBoard(bno,pageable);

        List<ReplyDTO> dtoList = result.getContent().stream()
                .map(reply ->{
                        ReplyDTO replyDTO = modelMapper.map(reply,ReplyDTO.class);
                        replyDTO.setBno(reply.getBoard().getBno());
                        return replyDTO;
                })
                .collect(Collectors.toList());

        PageResponseDTO<ReplyDTO> pageResponseDTO = PageResponseDTO.<ReplyDTO>withAll()
                .pageRequestDTO(pageRequestDTO)
                .dtoList(dtoList)
                .total((int) result.getTotalElements())
                .build();

        return pageResponseDTO;
    }
}
