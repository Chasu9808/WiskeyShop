package com.busanit501.boot501.controller;

import com.busanit501.boot501.dto.BoardDTO;
import com.busanit501.boot501.dto.BoardListAllDTO;
import com.busanit501.boot501.dto.PageRequestDTO;
import com.busanit501.boot501.dto.PageResponseDTO;
import com.busanit501.boot501.service.BoardService;
import com.busanit501.boot501.service.MemberService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.io.File;
import java.nio.file.Files;
import java.util.List;

// 화면, 데이터 같이 전달.
@Controller
@RequestMapping("/board")
@Log4j2
@RequiredArgsConstructor
public class BoardController {
    // c 드라이브에 업로드가 된 위치 경로
    @Value("${com.busanit501.upload.path}")
    private String uploadPath;

    private final BoardService boardService;
    private final MemberService memberService;

    //깃 테스트2
//깃 테스트3
    // ex) /board/list
    @GetMapping("/list")
    public void list(@AuthenticationPrincipal UserDetails user, PageRequestDTO pageRequestDTO, Model model) {

        log.info("BoardController : /board/list  확인 중, pageRequestDTO : " + pageRequestDTO);

        // dto 변경하기, 메서드도 변경하기. 댓글 갯수 포함, 첨부 이미지들 모두 포함.
        PageResponseDTO<BoardListAllDTO> responseDTO
                = boardService.listWithAll(pageRequestDTO);

        // 로그인 유저의 , 정보 가져오기.
//        boolean loginCheck = false;
//        memberService.
//        if ()

        // 서버로부터 응답확인.
        log.info("BoardController 확인 중, responseDTO : " + responseDTO);
        log.info("BoardController 확인 중, user : " + user);
        // 서버 -> 화면 데이터 전달.
        model.addAttribute("responseDTO", responseDTO);
        // 로그인 여부에 따라, 로그 아웃 표시하기.
        model.addAttribute("user", user);

    } //list 닫는 부분

    //글쓰기 폼
    @GetMapping("/register")
    public void registerForm(@AuthenticationPrincipal UserDetails user, Model model) {
        // 로그인 여부에 따라, 로그 아웃 표시하기.
        model.addAttribute("user", user);
    }

    //글쓰기 처리
    // 로그인한 유저이고, 일반 유저, 글쓰기가 가능하게끔 설정.
//    @PreAuthorize("isAuthenticated()")
    @PostMapping("/register")
    public String register(@Valid BoardDTO boardDTO
            , BindingResult bindingResult
            , RedirectAttributes redirectAttributes
            , Model model) {
        // 입력중 유효성 체크에 해당 될 때
        if (bindingResult.hasErrors()) {
            log.info("register 중 오류 발생.");
            redirectAttributes.addFlashAttribute(
                    "errors", bindingResult.getAllErrors());
            return "redirect:/board/register";
        }
        log.info("화면에서 입력 받은 내용 확인 : " + boardDTO);

        //화면 -> 서버 -> 서비스 -> 레포지토리 -> 디비, 입력후, 게시글 번호 가져오기
        //화면 <- 서버 <- 서비스 <- 레포지토리 <- 디비
        Long bno = boardService.register(boardDTO);

        // 글쓰기 후, 작성된 게시글 번호 -> 화면 , 임시로 전달.(1회용)
        redirectAttributes.addFlashAttribute("result", bno);
        redirectAttributes.addFlashAttribute("resultType", "register");
        return "redirect:/board/list";

    }

    //하나 조회 = 상세화면, read
    // 준비물, 해당 게시글 번호로 조회한 데이터가 필요함.
    // 화면 -> 서버로 , bno 게시글 번호를 전달하기.
//    @PreAuthorize("principal.username == #boardDTO2.writer")
    @GetMapping({"/read", "/update"})
    public void read(@AuthenticationPrincipal UserDetails user, Long bno, BoardDTO boardDTO2, PageRequestDTO pageRequestDTO, Model model) {

//        log.info("BoardController : boardDTO2 확인 중, boardDTO2 : " + boardDTO2.getWriter());
        log.info("BoardController : /board/read  확인 중, pageRequestDTO : " + pageRequestDTO);

        // 디비에서, bno 번호, 하나의 게시글 디비 정보 가져오기.
        BoardDTO boardDTO = boardService.read(bno);
        // 서버로부터 응답확인.
        log.info("BoardController 확인 중, boardDTO : " + boardDTO);
        // 서버 -> 화면 데이터 전달.
        model.addAttribute("boardDTO", boardDTO);
        model.addAttribute("user", user);

    } //read 닫는 부분

    //글수정 처리, 로직 처리만 막는 걸로.
    @PreAuthorize("principal.username == #boardDTO.writer")
    @PostMapping("/update")
    public String update(@Valid BoardDTO boardDTO
            , BindingResult bindingResult
            , RedirectAttributes redirectAttributes
            , @AuthenticationPrincipal UserDetails user
            , Model model
            , PageRequestDTO pageRequestDTO) {
        // 입력중 유효성 체크에 해당 될 때
        if (bindingResult.hasErrors()) {
            log.info("update 중 오류 발생.");
            redirectAttributes.addFlashAttribute(
                    "errors", bindingResult.getAllErrors());
            // 서버 -> 화면으로 쿼리 스트링으로전달.
            // 예시 : ?bno=게시글번호
            redirectAttributes.addAttribute("bno", boardDTO.getBno());
            return "redirect:/board/update" + pageRequestDTO.getLink();
        }
        log.info("화면에서 입력 받은 내용 update 확인 : " + boardDTO);

        //화면 -> 서버 -> 서비스 -> 레포지토리 -> 디비, 입력후, 게시글 번호 가져오기
        //화면 <- 서버 <- 서비스 <- 레포지토리 <- 디비
        boardService.update(boardDTO);

        // 글쓰기 후, 작성된 게시글 번호 -> 화면 , 임시로 전달.(1회용)
        redirectAttributes.addFlashAttribute("result", boardDTO.getBno());
        redirectAttributes.addFlashAttribute("resultType", "update");
        model.addAttribute("user", user);

        return "redirect:/board/list?" + pageRequestDTO.getLink2();

    }

    //글삭제 처리
    // principal.username: 로그인한 유저
    // #boardDTO.writer : 작성자
    @PreAuthorize("principal.username == #boardDTO.writer")
    @PostMapping("/delete")
    public String delete(BoardDTO boardDTO, PageRequestDTO pageRequestDTO, Long bno, RedirectAttributes redirectAttributes
    ) {


        //화면 -> 서버 -> 서비스 -> 레포지토리 -> 디비, 입력후, 게시글 번호 가져오기
        //화면 <- 서버 <- 서비스 <- 레포지토리 <- 디비
        // 데이터베이스에서 , 댓글, 첨부된 이미지들도 다 삭제
        boardService.deleteAll(bno);
        log.info("delete : boardDTO 확인 : " + boardDTO);
        // 미디어서버,  , 파일들도 다 같이 삭제.
        List<String> fileNames = boardDTO.getFileNames();
        if (fileNames != null && fileNames.size() > 0) {
            removeFiles(fileNames);
        }

        // 글쓰기 후, 작성된 게시글 번호 -> 화면 , 임시로 전달.(1회용)
        redirectAttributes.addFlashAttribute("result", bno);
        redirectAttributes.addFlashAttribute("resultType", "delete");
        return "redirect:/board/list?" + pageRequestDTO.getLink2();

    }


    public void removeFiles(List<String> files) {
        for (String fileName : files) {
            Resource resource = new FileSystemResource(
                    uploadPath + File.separator + fileName);
            String resourceName = resource.getFilename();
            // 결과 알려줄 임시 맵
//            Map<String,Boolean> resultMap = new HashMap<>();
            boolean deleteCheck = false;
            try {
                // 원본 파일 삭제
                // contentType , 섬네일 삭제시 이용할 예정.
                String contentType = Files.probeContentType(resource.getFile().toPath());
                deleteCheck = resource.getFile().delete();
                if (contentType.startsWith("image")) {
                    File thumbnailFile = new File(uploadPath + File.separator
                            + "s_" + fileName);
                    thumbnailFile.delete();
                }
            } catch (Exception e) {
                log.error(e.getMessage());
            }
//            resultMap.put("result",deleteCheck);
//            return resultMap;
        }
    }


} // BoardController 닫는 부분
