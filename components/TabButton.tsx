
import React from 'react';

interface Props {
  isActive: boolean;
  onClick: () => void;
  children: React.ReactNode;
}

export const TabButton: React.FC<Props> = ({ isActive, onClick, children }) => {
  const baseClasses = "flex items-center space-x-2 text-sm sm:text-base font-medium py-3 px-4 sm:px-6 transition-colors duration-200 ease-in-out focus:outline-none";
  const activeClasses = "border-b-2 border-blue-500 text-blue-600";
  const inactiveClasses = "text-gray-500 hover:text-gray-800 hover:bg-gray-100 rounded-t-lg";

  return (
    <button
      onClick={onClick}
      className={`${baseClasses} ${isActive ? activeClasses : inactiveClasses}`}
    >
      {children}
    </button>
  );
};
