const getTimeAgo = (regDate) => {
    const now = new Date();
    const date = new Date(regDate);
  
    let yearDiff = now.getFullYear() - date.getFullYear();
    let monthDiff = now.getMonth() - date.getMonth();
    let dayDiff = now.getDate() - date.getDate();
  
    if (dayDiff < 0) {
      monthDiff -= 1;
      dayDiff += new Date(now.getFullYear(), now.getMonth(), 0).getDate();
    }
    if (monthDiff < 0) {
      yearDiff -= 1;
      monthDiff += 12;
    }
  
    const intervals = [
      { label: "년", value: yearDiff },
      { label: "개월", value: monthDiff },
      { label: "일", value: dayDiff },
      { label: "시간", value: Math.floor((now - date) / 3600000) % 24 },
      { label: "분", value: Math.floor((now - date) / 60000) % 60 },
      { label: "초", value: Math.floor((now - date) / 1000) % 60 },
    ];
  
    const result = intervals.find((interval) => interval.value > 0);
    return result ? `${result.value}${result.label} 전` : "방금 전";
  };
  
  export default getTimeAgo;