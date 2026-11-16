package io.aegis.loadtest;

import io.netty.channel.EventLoopGroup;
import io.netty.channel.IoHandlerFactory;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.ServerChannel;
import io.netty.channel.Channel;
import io.netty.channel.epoll.Epoll;
import io.netty.channel.epoll.EpollIoHandler;
import io.netty.channel.epoll.EpollServerSocketChannel;
import io.netty.channel.epoll.EpollSocketChannel;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import java.util.function.Supplier;

/** The event loop and channel types for one Netty transport: epoll where the platform has it, NIO otherwise. */
record Transport(
        Supplier<IoHandlerFactory> ioHandler,
        Class<? extends Channel> clientChannel,
        Class<? extends ServerChannel> serverChannel) {

    private static final Transport EPOLL =
            new Transport(EpollIoHandler::newFactory, EpollSocketChannel.class, EpollServerSocketChannel.class);
    private static final Transport NIO =
            new Transport(NioIoHandler::newFactory, NioSocketChannel.class, NioServerSocketChannel.class);

    static Transport best() {
        return Epoll.isAvailable() ? EPOLL : NIO;
    }

    EventLoopGroup newGroup(int threads) {
        return new MultiThreadIoEventLoopGroup(threads, ioHandler.get());
    }
}
