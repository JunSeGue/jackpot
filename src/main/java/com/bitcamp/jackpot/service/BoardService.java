package com.bitcamp.jackpot.service;

import com.bitcamp.jackpot.domain.Board;
import com.bitcamp.jackpot.dto.BoardDTO;
import com.bitcamp.jackpot.dto.PageRequestDTO;
import com.bitcamp.jackpot.dto.PageResponseDTO;

import java.util.List;

public interface BoardService {
//    void register(BoardDTO boardDTO);

    void register(Board board);

    BoardDTO findOne(Integer boardId);

    PageResponseDTO<BoardDTO> findAll(PageRequestDTO pageRequestDTO);

    PageResponseDTO<BoardDTO> findAllAsk(PageRequestDTO pageRequestDTO);

    List<BoardDTO> findAllAskMyPage(PageRequestDTO pageRequestDTO);

    BoardDTO edit(Integer boardId, Board board);

    void remove(Integer boardId);

    PageResponseDTO<BoardDTO> search(String keyword, PageRequestDTO pageRequestDTO);
}

