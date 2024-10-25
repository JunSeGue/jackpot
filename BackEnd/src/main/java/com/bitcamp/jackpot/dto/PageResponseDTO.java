package com.bitcamp.jackpot.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

import java.util.List;

// Controller에서 View로 Pagination하기 위해서 전송하는 클래스
@Getter
@ToString
public class PageResponseDTO<E> {

    private int page;           // 현재 페이지
    private int size;           // 페이지 크기
    private int total;          // 전체 row 개수

    private int start;          // 현재 페이지에서 시작 페이지 숫자
    private int end;            // 현재 페이지에서 끝 페이지 숫자

    private boolean prev;       // 이전 페이지 블록 존재 여부
    private boolean next;       // 다음 페이지 블록 존재 여부

    private List<E> dtoList;    // 현재 페이지에 보여줄 데이터 리스트

    @Builder(builderMethodName = "withAll")
    public PageResponseDTO(PageRequestDTO pageRequestDTO, List<E> dtoList, int total) {
        if (total <= 0) return;

        this.page = pageRequestDTO.getPage();
        this.size = pageRequestDTO.getSize();
        this.total = total;
        this.dtoList = dtoList;

        // Math.ceil을 사용하여 올림 처리
        this.end = (int) (Math.ceil(this.page / 10.0)) * 10;
        this.start = this.end - 9;

        int last = (int) (Math.ceil((total / (double) size)));
        this.end = end > last ? last : end;

        this.prev = this.start > 1;
        this.next = total > this.end * this.size;
    }
}
