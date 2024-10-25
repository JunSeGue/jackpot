import styled from "styled-components";

export const StyledInfo = styled.div`
  padding: 16px;
  gap: 32px;
  display: flex;
  flex-wrap: wrap;
  flex-direction: row;

  .title {
    width: 100%;
    font-size: 32px;
    font-weight: bold;
    letter-spacing: -1px;
    line-height: 50px;
    text-align: left;
  }
  .image-box {
    display: flex;
    flex: 1.5;
    max-height: 500px;
    width: 100%;
    overflow: hidden;
  }
  .mainImage {
    object-fit: scale-down;
    width: 100%;
    height: auto;
  }

  .right-section {
    flex: 1;
    width: 100%;
    flex-wrap: wrap;
    gap:30px;

    .category-section {
      font-size: 1rem; /* body2 크기와 동일 */
      width: 100%;
      color: ${(props) => props.theme.colors.blue};
      font-weight: bold;
      margin-right: 1rem;
      gap: 20px;
      margin-bottom: 30px;
    }
    .fundInfo-section {
      text-align: left;

      > .text-small {
        display: inline-block;
      }
    }
    .fundingAmount {
      font-size: 24px;
      font-weight: bold;
      margin-right: 8px;
    }
    .price-container {
      display: flex;
      justify-content: center;
      align-items: center;
      width: 100%;
      margin: 10px 0;
    }
  }
`;
