import React, { useState, useEffect } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { TrendingUp, TrendingDown, Activity, DollarSign, BarChart3 } from 'lucide-react';

const StockDisplay = () => {
  const [stockData, setStockData] = useState([]);
  const [selectedTimeframe, setSelectedTimeframe] = useState('1D');

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await fetch('/api/stock-data');
        const data = await response.json();
        setStockData(data);
      } catch (error) {
        console.error('Error fetching stock data:', error);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  const getStockTrend = (stock) => {
    return stock.price_change >= 0 ? (
      <div className="flex items-center text-green-500">
        <TrendingUp className="w-4 h-4 mr-1" />
        <span>+{stock.price_change.toFixed(2)}%</span>
      </div>
    ) : (
      <div className="flex items-center text-red-500">
        <TrendingDown className="w-4 h-4 mr-1" />
        <span>{stock.price_change.toFixed(2)}%</span>
      </div>
    );
  };

  return (
    <div className="space-y-4">
      <Tabs defaultValue="stocks" className="w-full">
        <TabsList>
          <TabsTrigger value="stocks">Stocks</TabsTrigger>
          <TabsTrigger value="charts">Charts</TabsTrigger>
        </TabsList>

        <TabsContent value="stocks">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {stockData.map((stock) => (
              <Card key={stock.symbol} className="hover:shadow-lg transition-shadow">
                <CardHeader>
                  <CardTitle className="flex justify-between items-center">
                    <span>{stock.symbol}</span>
                    {getStockTrend(stock)}
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    <div className="flex justify-between items-center">
                      <div className="flex items-center">
                        <DollarSign className="w-4 h-4 mr-1" />
                        <span>Price</span>
                      </div>
                      <span className="font-bold">${stock.price.toFixed(2)}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <div className="flex items-center">
                        <Activity className="w-4 h-4 mr-1" />
                        <span>Volume</span>
                      </div>
                      <span>{stock.volume.toLocaleString()}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <div className="flex items-center">
                        <BarChart3 className="w-4 h-4 mr-1" />
                        <span>Market Cap</span>
                      </div>
                      <span>${(stock.market_cap / 1e9).toFixed(2)}B</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="charts">
          <Card>
            <CardHeader>
              <CardTitle>Price History</CardTitle>
              <div className="flex space-x-2">
                {['1D', '1W', '1M', '3M', 'YTD'].map((timeframe) => (
                  <button
                    key={timeframe}
                    onClick={() => setSelectedTimeframe(timeframe)}
                    className={`px-3 py-1 rounded ${
                      selectedTimeframe === timeframe
                        ? 'bg-blue-500 text-white'
                        : 'bg-gray-200'
                    }`}
                  >
                    {timeframe}
                  </button>
                ))}
              </div>
            </CardHeader>
            <CardContent>
              <div className="h-96">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={stockData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="time" />
                    <YAxis domain={['auto', 'auto']} />
                    <Tooltip />
                    <Line
                      type="monotone"
                      dataKey="price"
                      stroke="#3b82f6"
                      strokeWidth={2}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default StockDisplay;