package com.bitcamp.jackpot.controller;


import com.bitcamp.jackpot.dto.ReplyDTO;
import com.bitcamp.jackpot.service.ReplyService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@CrossOrigin(origins = "http://localhost:12000")
@RestController
@RequestMapping("/reply")
@RequiredArgsConstructor
@Log4j2
public class ReplyController {

    // 프로퍼티
    private final ReplyService replyService;

    // 댓글 등록, create
    @PostMapping(value = "/register", consumes = MediaType.APPLICATION_JSON_VALUE)
    public void register(@RequestBody ReplyDTO replyDTO) {
        System.out.println(replyDTO);
        replyService.register(replyDTO);
        // 댓글 등록만 해서 리턴값 없음.
    }

    // 댓글 수정, update
//    @PostMapping("/")
//    public void edit(Integer Id, ReplyDTO replyDTO, Model model){
//        replyService.edit(Id, replyDTO);
//        model.addAttribute("editedReply", replyDTO);
//        // 수정 후에 수정된 댓글을 모델객체에 실어보냄.
//    }

    // 댓글 수정, update
    @PutMapping(value = "/edit/{replyId}", consumes = MediaType.APPLICATION_JSON_VALUE)
    public void edit(@PathVariable("replyId") Integer replyId, @RequestBody ReplyDTO replyDTO) {
        replyService.edit(replyId, replyDTO);
        // 특정 댓글(댓글 번호로 구분)을 기존 댓글내용위에 새로운 댓글내용을 덧씌우는 방식으로 댓글 수정함.
        // 수정된 댓글은 제이슨이나 모델(뷰 템플릿x)등으로 보내는게 아닌 그냥 새롭게 조회하면 됨.
    }

    // 댓글 삭제, delete
    @DeleteMapping("/remove/{replyId}")
    public void remove(@PathVariable("replyId") Integer replyId) {
        // 스프링은 스트링으로 오는 패스버라이어블 값을 자동으로 인티저 값으로 바꿔줌.
        // 그래서 명시적으로 밸류오브나 파스인트같은 메서드를 사용하지 않아도 됨.
        replyService.remove(replyId);
    }

//    // 댓글 전부 조회, read
//    @GetMapping("/findAll/{boardId}")
//    public ResponseEntity<List<ReplyDTO>> findAll(@PathVariable("boardId")Integer boardId){
//        List<ReplyDTO> replyDTOS = replyService.findAll(boardId);
//        return ResponseEntity
//                .status(HttpStatus.OK)
//                .body(replyDTOS);
//        // 리플라이디티오 리스트 리턴.
//    }

    // 댓글 전부 조회, read
    @GetMapping("/findAll")
    public ResponseEntity<List<ReplyDTO>> findAll(@RequestParam("boardId") Integer boardId) {
        List<ReplyDTO> replyDTOS = replyService.findAll(boardId);

        System.out.println(replyDTOS);

        return ResponseEntity
                .status(HttpStatus.OK)
                .body(replyDTOS);
    }


    //+ register(ReplyDTO replyDTO)

    //+ edit(int id, ReplyDTO replyDTO)

    //+ remove(int id)

    //+ findAll: List<ReplyDTO>
}
