package com.bitcamp.jackpot.controller;

import com.bitcamp.jackpot.domain.Board;
import com.bitcamp.jackpot.dto.BoardDTO;
import com.bitcamp.jackpot.dto.PageRequestDTO;
import com.bitcamp.jackpot.dto.PageResponseDTO;
import com.bitcamp.jackpot.repository.BoardRepository;
import com.bitcamp.jackpot.service.BoardService;
import com.bitcamp.jackpot.service.ReplyService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.validation.BindException;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;
import lombok.extern.log4j.Log4j2;

import java.util.List;

@RestController
@RequestMapping("/board")
@RequiredArgsConstructor
@Log4j2
public class BoardController {


    // 프로퍼티
    private final BoardService boardService;


    // 게시글 등록, create
    @PostMapping("/register")
    public ResponseEntity<String> register(@ModelAttribute Board board, BindingResult bindingResult) throws BindException {

        System.out.println(board);
//        log.info(board);

        try {
            boardService.register(board);
            String successPath = "\"status\":200";
            return ResponseEntity.ok(successPath);
            // BoardDTO유효성 검사(낫널, 낫임티 어노테이션)통과하면 트라이문 실행해서 글목록으로 이동함.
        } catch (Exception e) {
            log.error(e);
            String failPath = "\"status\":403";
            return ResponseEntity.ok(failPath);
            // BoardDTO유효성 검사 통과 못해서 익셉션 터지면 다시 글작성 페이지로 돌아감.
            // 근데 작성내용이 유지되는지는 모르겠네. 유지안되면 처음부터 다시 써야함.
        }
    }

    // 게시글 하나만 조회, read
    @GetMapping("/findOne")
    public ResponseEntity<?> findOne(@RequestParam Integer boardId) {
//        int boardId = Integer.valueOf(boardIdStr);
        //패스버라이어블은 스트링으로 받아오기때문에 인트값으로 바꿔줌. 수정 - 바꿔줄 필요 없음 자동으로 바뀜
        BoardDTO boardDTO = boardService.findOne(boardId);
        // 서비스단 메서드를 실행시켜 게시글 객체를 글번호로 검색해서 가져옴
        // 글 번호는 uri에 담아 가져옴
//        log.info(boardDTO);
        // 서비스단에서 객체를 제대로 잘 가져왔는가 로그찍어봄.
        return ResponseEntity
                .status(HttpStatus.OK)
                .body(boardDTO);
        // 리스폰스엔티티 객체에 찾은 게시글을 실어 보낸다.
    }

//    // 게시글 목록 조회, read
//    // 페이지네이션 구현 안되어있음.
//    @GetMapping("/findAll/{type}")
//    public List<BoardDTO> findAll(@PathVariable("type")String typeStr){
//    // 페이지네이션 관련 코드 필요? 10개씩 묶어서 프론트단으로 보내기?
//        int type =Integer.parseInt(typeStr);
//        return boardService.findAll(type);
//        // 보드디티오 리스트 리턴.
//    }

    // 자유게시판 게시글 목록 조회, read.
    @GetMapping("/findAll")
    public ResponseEntity<PageResponseDTO<BoardDTO>> findAll(PageRequestDTO pageRequestDTO) {
        PageResponseDTO<BoardDTO> pageResponseDTO = boardService.findAll(pageRequestDTO);
//        System.out.println(pageResponseDTO);
        return ResponseEntity
                .status(HttpStatus.OK)
                .body(pageResponseDTO);
        // 보드디티오 리스트 리턴. 그런데 전체 다 리턴하는게 아니라 열개만 리턴
        // 리스폰스엔티티에 페이지리스폰스디티오를 실어보냄.
    }

    // 1:1문의게시판 게시글 목록 조회, read.
    @GetMapping("/findAllAsk")
    public ResponseEntity<PageResponseDTO<BoardDTO>> findAllAsk(PageRequestDTO pageRequestDTO) {
        PageResponseDTO<BoardDTO> pageResponseDTO = boardService.findAllAsk(pageRequestDTO);
//        System.out.println(pageResponseDTO);
        return ResponseEntity
                .status(HttpStatus.OK)
                .body(pageResponseDTO);
        // 보드디티오 리스트 리턴. 그런데 전체 다 리턴하는게 아니라 열개만 리턴
        // 리스폰스엔티티에 페이지리스폰스디티오를 실어보냄.
    }

    // 1:1문의게시판마이페이지 게시글 목록 조회, read.
    @GetMapping("/findAllAskMyPage")
    public ResponseEntity<List<BoardDTO>> findAllAskMyPage(PageRequestDTO pageRequestDTO) {
        List<BoardDTO> boardDTOList = boardService.findAllAskMyPage(pageRequestDTO); // 메서드 호출 시 반환 타입에 맞춰 변수 수정
//        log.info(boardDTOList);
        return ResponseEntity
                .status(HttpStatus.OK)
                .body(boardDTOList); // 반환 타입에 맞춰서 boardDTOList를 사용
    }


//    // 게시글 수정, update
//    @PostMapping("/edit/{boardId}")
//    public ResponseEntity<String> edit(@PathVariable("boardId") String boardIdStr, @RequestBody @Valid BoardDTO boardDTO) {
//        int boardId = Integer.parseInt(boardIdStr);
//        try {
//            BoardDTO boardDTOEdit = boardService.edit(boardId, boardDTO);
//            String successPath = "/board/readOne/" + boardId;
//            return ResponseEntity.ok(successPath);
//            // BoardDTO유효성 검사(낫널, 낫임티 어노테이션)통과하면 트라이문 실행해서 글수정 메서드 실행 후
//            // 수정한 게시글 객체를 모델 객체에 실어 보냄. 그리고 수정한 게시글 조회페이지로 이동시킴. 수정한거 함 보라고.
//        } catch (Exception e) {
//            log.info(e);
//            String failPath = "/board/edit/" + boardId;
//            return ResponseEntity.ok(failPath);
//            // BoardDTO유효성 검사 통과 못해서 익셉션 터지면 수정 페이지로 다시 돌아감.
//            // 유효성 검사 통과 못하는 경우? 뭔가 칸을 비우고 저장버튼 눌렀을때.
//            // 근데 작성내용이 유지되는지는 모르겠네. 유지안되면 처음부터 다시 써야함.
//        }
//    }

        // 게시글 수정, update
    @PostMapping("/edit/{boardId}")
    public ResponseEntity<String> edit(@PathVariable("boardId") String boardIdStr, @ModelAttribute Board board) {
        int boardId = Integer.parseInt(boardIdStr);
        System.out.println(boardId);
        System.out.println(board);
        try {
            board.setBoardId(boardId);
            System.out.println(board);
            BoardDTO boardEditted = boardService.edit(boardId, board);
            String successPath = "/board/readOne/" + boardId;
            return ResponseEntity.ok(successPath);
            // BoardDTO유효성 검사(낫널, 낫임티 어노테이션)통과하면 트라이문 실행해서 글수정 메서드 실행 후
            // 수정한 게시글 객체를 모델 객체에 실어 보냄. 그리고 수정한 게시글 조회페이지로 이동시킴. 수정한거 함 보라고.
        } catch (Exception e) {
            log.info(e);
            String failPath = "/board/edit/" + boardId;
            return ResponseEntity.ok(failPath);
            // BoardDTO유효성 검사 통과 못해서 익셉션 터지면 수정 페이지로 다시 돌아감.
            // 유효성 검사 통과 못하는 경우? 뭔가 칸을 비우고 저장버튼 눌렀을때.
            // 근데 작성내용이 유지되는지는 모르겠네. 유지안되면 처음부터 다시 써야함.
        }
    }

    // 게시글 삭제, delete
    // 패스버라이어블은 uri에 담겨온 아이디를 매개변수로 받아 삭제함
    // 그렇기 때문에 스트링으로 오는데 인트로 바꿔줘야함
    @DeleteMapping("/remove/{boardId}")
    public void remove(@PathVariable Integer boardId) {

//        int boardId = Integer.valueOf(boardIdStr);
//        System.out.println(boardId);
        boardService.remove(boardId);
        // 인트값을 넣어서 리무브 메서드 실행해도 오토박싱되서 실행됨.
        // 게시글 삭제 시 게시글에 달린 댓글들도 삭제되게 해야 함.
    }

//    // 게시글 검색
//    // 패스버라이어블로 검색어를 uri로 받아오고 그걸로 검색함
//    // 프론트단에서 검색어를 uri에 넣어주세요~
//    // 페이지네이션 구현 안되어 있음
//    @GetMapping("/search/{keyword}")
//    public List<BoardDTO> search(@PathVariable String keyword) {
//        return boardService.search(keyword);
//        // 리턴값은 보드디티오 리스트, 키워드를 받아서 제목을 검색함. 검색하는 메서드는 레포지토리에.
//    }

    // 게시글 검색
    @GetMapping("/search")
    public PageResponseDTO<BoardDTO> search(@RequestParam("keyword") String keyword, PageRequestDTO pageRequestDTO) {

//        log.info(keyword);
//        log.info(pageRequestDTO);

        PageResponseDTO<BoardDTO> pageResponseDTO = boardService.search(keyword, pageRequestDTO);

//        log.info(pageResponseDTO);

        return pageResponseDTO;

//        return boardService.search(keyword, pageRequestDTO);
    }


}
