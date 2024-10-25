import React from "react";
import styled from "styled-components";

const fundStory = `
유기견 보호소에는 많은 강아지들이 새로운 가족을 기다리며 보호받고 있습니다.
하지만 보호소의 자원은 한정되어 있고, 강아지들을 지속적으로 돌보는 데는 많은 비용이 필요합니다.
보호소에서의 생활은 강아지들에게 최소한의 안전을 보장해주지만, 충분한 후원과 지원이 끊기면 더 이상 강아지들을 돌볼 수 없게 되어, 결국 안타까운 선택을 할 수밖에 없습니다.

이번 클라우드 펀딩은 이러한 유기견 보호소에 지속적인 후원을 제공하여 강아지들이 안전하게 지낼 수 있도록 돕는 데 목적이 있습니다. 
모인 후원금은 보호소에서 강아지들을 돌보고 관리하는 데 직접적으로 사용되며, 
여러분의 기부가 강아지들이 더 오랜 시간 보호소에서 안전하게 머무르며 새로운 가족을 찾을 수 있는 기회를 제공합니다.

이 후원은 단순한 금전적 지원이 아니라, 강아지들에게 새로운 희망을 주는 소중한 기회입니다. 
여러분의 따뜻한 마음이 모여, 많은 강아지들이 보호소에서 안전하게 머무를 수 있도록 도와주세요.
`;

const Section = styled.div`
  border: 3px solid ${(props) => props.theme.colors.paleOrange};
  width: 80%;
  border-radius: 10px;
  margin: 20px 0;
  padding: 0px;
  overflow: hidden;

  .story-section {
    word-break: break-word;
  }

  .top-name {
    background: ${(props) => props.theme.colors.orangeGradient};
    color: #fff;
    font-size: 18px;
    font-weight: 700;
    letter-spacing: -0.3px;
    width: 160px;
    height: 42px;
    justify-content: center;
    align-items: center;
    padding: 0 15px;
    line-height: 42px;
  }

  .discription-section {
    max-width: 900px;
    margin: 15px 30px;
  }

  .title {
    font-weight: 700;
    font-size: 30px;
    word-spacing: -0.75px;
    line-height: 1.5em;
    margin: 20px 0 0 0;
    padding: 1px 8px 1px;
    border-left: 3px solid blue;
    width: fit-content;
    color: #000;
  }

  .discription {
    white-space: pre-line;
    text-align: left;
    margin-top: 0;
    font-size: 1.2rem;
    padding: 20px 0;
  }
`;
const storySection = () => {
  return (
    <Section className="flex justify-center align-center">
      <div className="story-section flex flex-column justify-center align-start">
        <div className="top-name flex">프로젝트 소개</div>
        <div className="discription-section flex flex-column">
          <div className="title flex">유기견</div>
          <p className="discription flex">{fundStory}</p>
        </div>
      </div>
    </Section>
  );
};

export default storySection;
