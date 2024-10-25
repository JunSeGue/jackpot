import { createGlobalStyle } from "styled-components";

const GlobalStyle = createGlobalStyle`
  /* Regular 폰트 정의 */
  @font-face {
    font-family: "Noto Sans KR";
    src: url("/fonts/NotoSansKR-Regular.ttf") format("truetype");
    font-weight: 400;
    font-style: normal;
  }

  /* SemiBold 폰트 정의 */
  @font-face {
    font-family: "Noto Sans KR";
    src: url("/fonts/NotoSansKR-SemiBold.ttf") format("truetype");
    font-weight: 600;
    font-style: normal;
  }
  @font-face {
  font-family: "Noto Sans KR";
  src: url("/fonts/NotoSansKR-Bold.ttf") format("truetype");
  font-weight: 700;
  font-style: normal;
}

  /* ExtraBold 폰트 정의 */
 @font-face {
  font-family: "Noto Sans KR";
  src: url("/fonts/NotoSansKR-ExtraBold.ttf") format("truetype");
  font-weight: 900;
  font-style: normal;
}

  /* global config */
  /* 태그별 config*/
  html,
  body {
    overflow: auto; /* 스크롤 기능 유지 */
    -ms-overflow-style: none; /* IE 및 구형 Edge */
    scrollbar-width: none; /* Firefox */
  }

  body::-webkit-scrollbar {
    width: 0px; /* 웹킷 기반 브라우저에서 스크롤바 너비 없앰 */
    height: 0px; /* 가로 스크롤바 없앰 */
  }

  body {
    font-family: "Noto Sans KR", sans-serif;
    font-weight: 400; /* 기본 폰트는 Regular */
    margin: 0;
    padding: 0;
    width: 100vw;
    height: 100vh;
  }

  a {
    text-decoration: none; /* 기본 밑줄 제거 */
    cursor: pointer;
  }

  a:hover {
    text-decoration: underline; /* 마우스 오버 시 밑줄 추가 */
  }

  a:focus {
    outline: none; /* 포커스 시 기본 아웃라인 제거 */
    box-shadow: 0 0 0 2px rgba(0, 0, 0, 0.2); /* 포커스 시 시각적 표시 */
  }

  a:active {
    color: #d64229; /* 클릭된 상태일 때 색상 변화 */
  }

  p {
    white-space: normal;
    margin: 0;
    padding: 0;
  }

  ol,
  ul {
    list-style: none;
    margin: 0;
    padding: 0;
  }

  h1,
  h2,
  h3,
  h4,
  h5,
  h6 {
    margin: 0;
    padding: 0;
    font-weight: 600; /* SemiBold 적용 */
  }

  .container {
    margin-top: 100px;
    width: 100%;
    min-height: 100vh;
  }

  /* flex-area */
  .flex {
    display: flex;
  }

  .flex-row {
    flex-direction: row;
  }

  .flex-column {
    flex-direction: column;
  }
  .flex-wrap {
    flex-wrap: wrap;
  }

  .justify-center {
    justify-content: center;
  }

  .justify-between {
    justify-content: space-between;
  }

  .justify-around {
    justify-content: space-around;
  }

  .justify-start {
    justify-content: flex-start;
  }

  .justify-end {
    justify-content: flex-end;
  }

  .align-center {
    align-items: center;
  }

  .align-start {
    align-items: flex-start;
  }

  .align-end {
    align-items: flex-end;
  }

  /* margin & padding Area  */

  /* Margin 관련 */
  .m-0 {
    margin: 0;
  }

  .m-1 {
    margin: 5px;
  }

  .m-2 {
    margin: 10px;
  }

  .m-3 {
    margin: 15px;
  }

  .m-4 {
    margin: 20px;
  }

  .m-auto {
    margin: auto;
  }

  /* Padding 관련 */
  .p-0 {
    padding: 0;
  }

  .p-1 {
    padding: 5px;
  }

  .p-2 {
    padding: 10px;
  }

  .p-3 {
    padding: 15px;
  }

  .p-4 {
    padding: 20px;
  }

  .opacity-0 {
    opacity: 0;
  }

  .opacity-50 {
    opacity: 0.5;
  }

  .opacity-100 {
    opacity: 1;
  }

  /* Text 관련 */
  .text-left {
    text-align: left;
  }

  .text-center {
    text-align: center;
  }

  .text-right {
    text-align: right;
  }

  .text-bold {
    font-weight: bold;
  }

  .text-normal {
    font-weight: normal;
  }

  .text-small {
    font-size: 12px;
  }

  .text-medium {
    font-size: 16px;
  }

  .text-large {
    font-size: 24px;
  }

  /* 상대적인 크기를 사용할 수도 있습니다 */
  .text-relative {
    font-size: 1.5em; /* 부모 요소의 크기에 따라 상대적으로 설정 */
  }

  /* Width 관련 */

  .w-full {
    width: 100%;
  }

  .w-eighty {
    width: 80%;
  }

  .w-half {
    width: 50%;
  }

  .w-thirty {
    width: 30%;
  }

  .w-auto {
    width: auto;
  }

  /* Height 관련 */
  .h-full {
    height: 100%;
  }

  .h-auto {
    height: auto;
  }

  /* Position 관련 */
  .relative {
    position: relative;
  }

  .absolute {
    position: absolute;
  }

  .fixed {
    position: fixed;
  }

  .top-0 {
    top: 0;
  }

  .left-0 {
    left: 0;
  }

  .d-block {
    display: block;
  }

  .d-inline {
    display: inline;
  }

  .d-inline-block {
    display: inline-block;
  }

  .d-none {
    display: none;
  }

  /* grid */
  .grid {
    display: grid;
  }

  .grid-cols-2 {
    grid-template-columns: repeat(2, 1fr); /* 2열 그리드 */
  }

  .grid-cols-3 {
    grid-template-columns: repeat(3, 1fr); /* 3열 그리드 */
  }

  .grid-cols-4 {
    grid-template-columns: repeat(4, 1fr); /* 4열 그리드 */
  }

  .grid-auto-rows {
    grid-auto-rows: auto; /* 자동 행 크기 설정 */
  }

  .grid-center {
    justify-items: center; /* 그리드 아이템 수평 중앙 정렬 */
    align-items: center; /* 그리드 아이템 수직 중앙 정렬 */
  }

  /* cursor */
  .pointer {
    cursor: pointer;
  }

  .textCursor {
    cursor: text;
  }

  .waitCursor {
    cursor: wait;
  }

  [class^="btn_"] {
    font-size: 16px;
    line-height: 1;
    text-align: center;
    transition: opacity 0.3s ease-in-out; /* opacity에만 부드러운 애니메이션 적용 */
    cursor: pointer;
    padding: 10px 20px;
    border: none;
    border-radius: 5px; /* 버튼 모서리 둥글게 설정 */
    opacity: 0.8; /* 기본 상태에서 약간 투명하게 설정 */
  }

  /* 호버 시 페이드 인 효과 */
  [class^="btn_"]:hover {
    background-color: rgba(
      128,
      128,
      128,
      0.5
    ); /* 회색으로 오파시티가 적용된 배경색 */
    opacity: 0.8; /* 호버 시 약간 투명하게 설정 */
    cursor: pointer;
  }

  [class^="section-"] {
    background-color: #ffffff;
    border-radius: 4px; /* 모서리 둥글게 처리 */
    box-shadow: 0px 2px 4px rgba(0, 0, 0, 0.1); /* 가벼운 그림자 */
    padding: 16px; /* 내부 여백 */
    overflow: hidden; /* 내용 넘치면 숨기기 */
  }
`;

export default GlobalStyle;
