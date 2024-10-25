package com.bitcamp.jackpot.service;

import com.bitcamp.jackpot.dto.ReplyDTO;

import java.util.List;

public interface ReplyService {

    void register(ReplyDTO replyDTO);

    ReplyDTO edit(Integer replyId, ReplyDTO replyDTO);

    void remove(Integer replyId);

    List<ReplyDTO> findAll(Integer boardId);

    // 클래스 다이어그램

    //+ register(ReplyDTO ReplyDTO)

    //+ edit(int id, ReplyDTO replyDTO): ReplyDTO

    //+ remove(Int Id): void

    //+ findAll: List<ReplyDTO>

}
