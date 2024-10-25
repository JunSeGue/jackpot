package com.bitcamp.jackpot.service;


import com.bitcamp.jackpot.dto.MemberDTO;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.Map;


public interface MemberService {

     void signUp(MemberDTO memberDTO);

     void edit(MemberDTO memberDTO);

     void remove(String email);

     MemberDTO findOne(String email);

     Page<MemberDTO> findAll(int page, int size);

     Map<String, Boolean> checkEmail(String email);

     Map<String, Boolean> checkPwd(String email,String pwd);
     Map<String, Boolean> checkNickName(String nickName);

     String findId(String name, String phone);

     boolean resetPwd(String email,String pwd);

     void adminRemove(int memberId);

     void adminEdit(int memberId, MemberDTO memberDTO);

     Page<MemberDTO> searchMembersByName(String name, Pageable pageable);


}