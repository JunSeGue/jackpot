package com.bitcamp.jackpot.controller;

import com.bitcamp.jackpot.dto.SignInDTO;
import com.bitcamp.jackpot.jwt.CustomUserDetails;
import com.bitcamp.jackpot.dto.MemberDTO;
import com.bitcamp.jackpot.service.LogoutService;
import com.bitcamp.jackpot.service.MemberService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/member")
public class MemberController {

    private final MemberService memberService;
    private final LogoutService logoutService;

    //회원가입
    @PostMapping("/signUp")
    public ResponseEntity<String> signUp(@RequestBody @Valid MemberDTO memberDTO) {
        //회원가입처리
        memberService.signUp(memberDTO);


        return ResponseEntity
                .status(HttpStatus.CREATED) // 201 Created
                .body(memberDTO.getEmail());
    }

    @GetMapping("/myPage")
    public ResponseEntity<MemberDTO> getMyPage(@AuthenticationPrincipal CustomUserDetails customUserDetails) {
        String email = customUserDetails.getUsername();
        MemberDTO memberDTO = memberService.findOne(email);
        return ResponseEntity.ok(memberDTO);
    }

    @PutMapping("/edit")
    public ResponseEntity<Void> edit(@RequestBody MemberDTO memberDTO) {
        memberService.edit(memberDTO);
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/remove")
    public ResponseEntity<Void> remove(@AuthenticationPrincipal CustomUserDetails customUserDetails, HttpServletRequest request, HttpServletResponse response) {
        String email = customUserDetails.getUsername();

        memberService.remove(email);
        logoutService.logout(request, response);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/checkEmail")
    public ResponseEntity<Map<String, Boolean>> checkEmail(@RequestParam String email) {
        Map<String, Boolean> response = memberService.checkEmail(email);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/checkPwd")
    public ResponseEntity<Map<String, Boolean>> checkPwd(@AuthenticationPrincipal CustomUserDetails customUserDetails, @RequestParam String pwd) {
        String email = customUserDetails.getUsername();
        Map<String, Boolean> response = memberService.checkPwd(email, pwd);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/checkNickName")
    public ResponseEntity<Map<String, Boolean>> checkNickName(@RequestParam String nickName) {
        Map<String, Boolean> response = memberService.checkNickName(nickName);
        return ResponseEntity.ok(response);
    }


    @GetMapping("/findOne")
    public ResponseEntity<MemberDTO> getMember(@RequestParam String email) {

        MemberDTO memberDTO = memberService.findOne(email);
        return ResponseEntity.ok(memberDTO);  // 성공 시, OK 상태와 함께 MemberDTO 반환
    }


    @GetMapping("/findId")
    public ResponseEntity<String> findId(@RequestParam String name, String phone) {
        String email = memberService.findId(name, phone);
        return ResponseEntity.ok(email);
    }


@PatchMapping("/resetPwd")
public ResponseEntity<String> resetPwd(@RequestBody SignInDTO signInDTO) {
    memberService.resetPwd(signInDTO.getEmail(), signInDTO.getPwd());
        return ResponseEntity.ok("비밀번호 변경 성공");
    }


    @GetMapping("/search")
    public ResponseEntity<Page<MemberDTO>> searchMembers(
            @RequestParam("name") String name,
            Pageable pageable) {
        Page<MemberDTO> members = memberService.searchMembersByName(name, pageable);
        return new ResponseEntity<>(members, HttpStatus.OK);

    }


}